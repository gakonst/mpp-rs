//! Tempo Charge provider backed by the Tempo Accounts store.

use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};

use alloy::providers::Provider;
use tempo_alloy::accounts::{
    TempoAccountsError, TempoAccountsStore, TempoAccountsWallet, TempoAuthorizationReservation,
};
use tempo_alloy::{rpc::TempoTransactionRequest, TempoNetwork};

use super::{
    autoswap::AutoswapConfig,
    charge::SignOptions,
    session::{store::ChannelStore, TempoSessionProvider},
    signing::{KeychainVersion, TempoSigningMode},
};
use crate::{
    client::{PaymentContext, PaymentProvider},
    error::{MppError, ResultExt},
    protocol::core::{PaymentChallenge, PaymentCredential},
    protocol::methods::tempo::network::TempoNetwork as TempoChain,
};

/// A Tempo Charge provider that selects access keys lazily from Tempo
/// Accounts.
///
/// The wallet owns account, key, signature-type, scope, and pending
/// authorization selection. Callers do not configure a signing mode.
#[derive(Clone)]
pub struct TempoAccountsProvider {
    wallet: TempoAccountsWallet,
    rpc_url: Option<reqwest::Url>,
    client_id: Option<String>,
    autoswap: Option<AutoswapConfig>,
    expected_chain_id: Option<u64>,
    pending_authorizations: Arc<Mutex<HashMap<String, TempoAuthorizationReservation>>>,
    session: Option<AccountsSession>,
}

#[derive(Clone)]
struct AccountsSession {
    store: Arc<dyn ChannelStore>,
    provider: Arc<Mutex<Option<TempoSessionProvider>>>,
    default_deposit: Option<u128>,
    top_up_amount: Option<u128>,
    max_deposit: Option<u128>,
}

enum ExecutableAccountsWallet {
    Ready(TempoAccountsWallet),
    Rejected(MppError),
}

fn is_access_key_rejection(error: &alloy::transports::TransportError) -> bool {
    let Some(payload) = error.as_error_resp() else {
        return false;
    };
    if payload.code == 3 {
        return true;
    }

    // Tempo reports keychain validation failures as JSON-RPC -32603 rather
    // than the EVM revert code. Match only deterministic key failures here;
    // rate limits and other RPC/server errors must fail the whole preflight.
    let message = error.to_string().to_ascii_lowercase();
    [
        "keychain validation failed",
        "keynotfound",
        "key not found",
        "signaturetypemismatch",
        "spendinglimitexceeded",
        "spending limit exceeded",
        "access key is revoked",
        "access key has expired",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

impl TempoAccountsProvider {
    /// Create a Charge provider from a Tempo Accounts wallet.
    ///
    /// The settlement RPC is selected from the charge's chain ID. Use
    /// [`with_rpc_url`](Self::with_rpc_url) only for a custom network.
    pub fn new(wallet: TempoAccountsWallet) -> Self {
        Self {
            wallet,
            rpc_url: None,
            client_id: None,
            autoswap: None,
            expected_chain_id: None,
            pending_authorizations: Arc::new(Mutex::new(HashMap::new())),
            session: None,
        }
    }

    /// Open a specific Tempo Accounts store.
    pub fn from_store(path: impl AsRef<Path>) -> Result<Self, MppError> {
        let wallet = TempoAccountsWallet::from_store(path.as_ref())
            .mpp_config("failed to open Tempo Accounts store")?;
        Ok(Self::new(wallet))
    }

    /// Open the default Tempo Accounts store.
    pub fn from_default_store() -> Result<Self, MppError> {
        let wallet = TempoAccountsWallet::from_default_store()
            .mpp_config("failed to open Tempo Accounts store")?;
        Ok(Self::new(wallet))
    }

    /// Override the settlement RPC for custom networks.
    pub fn with_rpc_url(mut self, rpc_url: reqwest::Url) -> Self {
        self.rpc_url = Some(rpc_url);
        self
    }

    /// Set an optional client identifier for attribution memos.
    pub fn with_client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Enable an atomic stablecoin swap before payment.
    pub fn with_autoswap(mut self, config: AutoswapConfig) -> Self {
        self.autoswap = Some(config);
        self
    }

    /// Get the autoswap configuration, if set.
    pub fn autoswap(&self) -> Option<&AutoswapConfig> {
        self.autoswap.as_ref()
    }

    fn fee_token(&self) -> Option<alloy::primitives::Address> {
        self.autoswap.as_ref().map(|config| config.token_in)
    }

    /// Pin the chain ID this provider will pay on.
    pub fn with_expected_chain_id(mut self, chain_id: u64) -> Self {
        self.expected_chain_id = Some(chain_id);
        self
    }

    /// Get the pinned expected chain ID, if set.
    pub fn expected_chain_id(&self) -> Option<u64> {
        self.expected_chain_id
    }

    /// Get the lazy Accounts wallet.
    pub const fn wallet(&self) -> &TempoAccountsWallet {
        &self.wallet
    }

    /// Get the explicit settlement RPC override, if configured.
    pub const fn rpc_url(&self) -> Option<&reqwest::Url> {
        self.rpc_url.as_ref()
    }

    /// Build a matching session provider from the same Accounts wallet.
    ///
    /// The returned provider uses the exact access key selected for the pinned
    /// chain and delegates durable channel persistence to `channel_store`.
    pub fn session_provider(
        &self,
        channel_store: Arc<dyn ChannelStore>,
    ) -> Result<TempoSessionProvider, MppError> {
        let chain_id = self.expected_chain_id.ok_or_else(|| {
            MppError::InvalidConfig(
                "Tempo Accounts session provider requires an expected chain ID".to_owned(),
            )
        })?;
        let key = self
            .wallet
            .clone()
            .with_chain_id(chain_id)
            .active_access_key()
            .mpp_config("failed to select a Tempo Accounts session key")?;
        let account = key.account();
        let access_key = key.address();
        let key_authorization = key.key_authorization().cloned().map(Box::new);
        let rpc_url = self.settlement_rpc_url(chain_id)?;
        let mut provider = TempoSessionProvider::new(key, rpc_url.as_str())?
            .with_signing_mode(TempoSigningMode::Keychain {
                wallet: account,
                key_authorization,
                version: KeychainVersion::V2,
            })
            .with_authorized_signer(access_key)
            .with_channel_store(channel_store);
        if let Some(config) = &self.autoswap {
            provider = provider.with_autoswap(config.clone());
        }
        Ok(provider)
    }

    /// Enable durable payment sessions alongside one-time charges.
    pub fn with_session_store(mut self, store: Arc<dyn ChannelStore>) -> Self {
        self.session = Some(AccountsSession {
            store,
            provider: Arc::new(Mutex::new(None)),
            default_deposit: None,
            top_up_amount: None,
            max_deposit: None,
        });
        self
    }

    /// Set the deposit used when a session challenge does not suggest one.
    pub fn with_session_default_deposit(mut self, amount: u128) -> Self {
        if let Some(session) = self.session.as_mut() {
            session.default_deposit = Some(amount);
        }
        self
    }

    /// Set the preferred automatic session top-up size in atomic units.
    pub fn with_session_top_up_amount(mut self, amount: u128) -> Self {
        if let Some(session) = self.session.as_mut() {
            session.top_up_amount = Some(amount);
        }
        self
    }

    /// Cap the deposit that an automatic session may reserve.
    pub fn with_session_max_deposit(mut self, amount: u128) -> Self {
        if let Some(session) = self.session.as_mut() {
            session.max_deposit = Some(amount);
        }
        self
    }

    fn configured_session_provider(&self) -> Result<TempoSessionProvider, MppError> {
        let session = self.session.as_ref().ok_or_else(|| {
            MppError::UnsupportedPaymentMethod("tempo.session is not configured".to_owned())
        })?;
        let mut cached = session.provider.lock().map_err(|_| {
            MppError::InvalidConfig("Tempo Accounts session state is unavailable".to_owned())
        })?;
        if let Some(provider) = cached.as_ref() {
            return Ok(provider.clone());
        }
        let mut provider = self.session_provider(session.store.clone())?;
        if let Some(amount) = session.default_deposit {
            provider = provider.with_default_deposit(amount);
        }
        if let Some(amount) = session.top_up_amount {
            provider = provider.with_top_up_amount(amount);
        }
        if let Some(amount) = session.max_deposit {
            provider = provider.with_max_deposit(amount);
        }
        *cached = Some(provider.clone());
        Ok(provider)
    }

    /// Return whether the Accounts store has a locally signable key covering
    /// this charge's complete call intent.
    pub async fn has_access_key_for_challenge(
        &self,
        challenge: &PaymentChallenge,
    ) -> Result<bool, MppError> {
        let from = self
            .wallet
            .active_account()
            .mpp_config("failed to read the active Tempo account")?;
        let charge = super::provider::prepare_charge_request(
            challenge,
            self.expected_chain_id,
            self.client_id.as_deref(),
        )?;
        if charge.amount().is_zero() {
            return match self
                .wallet
                .clone()
                .with_chain_id(charge.chain_id())
                .active_access_key()
            {
                Ok(key) => Ok(key.account() == from),
                Err(TempoAccountsError::MissingAccessKey { .. }) => Ok(false),
                Err(error) => Err(error).mpp_config("failed to inspect Tempo Accounts access key"),
            };
        }

        let rpc_provider = super::rpc_provider(self.settlement_rpc_url(charge.chain_id())?);
        let charge =
            super::provider::apply_autoswap(charge, self.autoswap.as_ref(), &rpc_provider, from)
                .await?;
        let request = charge.accounts_request(from)?;
        self.prepare_executable_wallet(&rpc_provider, &request, from, charge.chain_id())
            .await
            .map(|prepared| matches!(prepared, ExecutableAccountsWallet::Ready(_)))
    }

    /// Select an access key whose complete transaction succeeds against the
    /// latest chain state, then pin that exact key through signing.
    ///
    /// Accounts store metadata describes a key's original policy, but spending
    /// limits are consumed on-chain. A scope-only selection can therefore sign
    /// a transaction with a depleted key even when a later stored key can pay.
    /// `eth_call` understands Tempo's `keyId` and `keyType` simulation fields,
    /// so it is the authoritative and side-effect-free check for the whole call
    /// batch (including approvals, swaps, and transfers).
    async fn prepare_executable_wallet<P>(
        &self,
        provider: &P,
        request: &TempoTransactionRequest,
        account: alloy::primitives::Address,
        chain_id: u64,
    ) -> Result<ExecutableAccountsWallet, MppError>
    where
        P: Provider<TempoNetwork>,
    {
        let candidates = if let Some(path) = self.wallet.store_path() {
            TempoAccountsStore::open(path)
                .mpp_config("failed to open Tempo Accounts store")?
                .access_keys()
                .mpp_config("failed to inspect Tempo Accounts access keys")?
                .into_iter()
                .filter(|key| {
                    key.account() == account
                        && key.chain_id() == chain_id
                        && key.is_locally_signable()
                })
                .map(|key| (key.address(), key.key_type()))
                .collect::<Vec<_>>()
        } else {
            let key = self
                .wallet
                .clone()
                .with_chain_id(chain_id)
                .active_access_key()
                .mpp_config("failed to select Tempo Accounts access key")?;
            vec![(key.address(), key.signature_type())]
        };

        let mut last_rejection = None;
        for (key_id, key_type) in candidates {
            let mut candidate_request = request.clone();
            candidate_request.key_id = Some(key_id);
            candidate_request.key_type = Some(key_type);
            let prepared = match self
                .wallet
                .prepare_request(provider, &mut candidate_request)
                .await
            {
                Ok(prepared) => prepared,
                Err(error) if error.is_local_usage_error() => {
                    last_rejection = Some(MppError::InvalidConfig(format!(
                        "Tempo access key {key_id} cannot prepare this payment: {error}"
                    )));
                    continue;
                }
                Err(error) => {
                    return Err(error).mpp_http("failed to prepare Tempo Accounts access key");
                }
            };

            match provider.call(candidate_request).await {
                Ok(_) => return Ok(ExecutableAccountsWallet::Ready(prepared)),
                Err(error) if is_access_key_rejection(&error) => {
                    let rejection = super::TempoClientError::from_transport_error(&error)
                        .map(MppError::from)
                        .unwrap_or_else(|| {
                            MppError::Http(format!(
                                "Tempo access key {key_id} rejected payment preflight: {error}"
                            ))
                        });
                    last_rejection = Some(rejection);
                }
                Err(error) => {
                    return Err(error).mpp_http("failed to preflight Tempo payment");
                }
            }
        }

        Ok(ExecutableAccountsWallet::Rejected(
            last_rejection.unwrap_or_else(|| {
                MppError::InvalidConfig(format!(
                    "no locally signable Tempo access key for account {account} on chain {chain_id} covers this payment"
                ))
            }),
        ))
    }

    fn settlement_rpc_url(&self, chain_id: u64) -> Result<reqwest::Url, MppError> {
        if let Some(url) = &self.rpc_url {
            return Ok(url.clone());
        }
        let network = TempoChain::from_chain_id(chain_id).ok_or_else(|| {
            MppError::InvalidConfig(format!(
                "unknown chain ID {chain_id}: configure an explicit settlement RPC URL"
            ))
        })?;
        network
            .default_rpc_url()
            .parse()
            .mpp_config("invalid default Tempo RPC URL")
    }

    fn remember_authorization(
        &self,
        challenge_id: &str,
        reservation: TempoAuthorizationReservation,
    ) -> Result<(), MppError> {
        let mut pending = self.pending_authorizations.lock().map_err(|_| {
            MppError::InvalidConfig(
                "Tempo authorization lifecycle state is unavailable".to_string(),
            )
        })?;
        match pending.entry(challenge_id.to_string()) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(reservation);
            }
            std::collections::hash_map::Entry::Occupied(entry) if *entry.get() == reservation => {}
            std::collections::hash_map::Entry::Occupied(_) => {
                return Err(MppError::InvalidConfig(format!(
                    "challenge {challenge_id} already has a different Tempo authorization in flight"
                )));
            }
        }
        Ok(())
    }

    fn take_authorization(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<Option<TempoAuthorizationReservation>, MppError> {
        if credential.challenge.id != challenge.id {
            return Err(MppError::InvalidConfig(
                "payment lifecycle credential does not match its challenge".to_string(),
            ));
        }
        self.pending_authorizations
            .lock()
            .map_err(|_| {
                MppError::InvalidConfig(
                    "Tempo authorization lifecycle state is unavailable".to_string(),
                )
            })
            .map(|mut pending| pending.remove(&challenge.id))
    }
}

impl PaymentProvider for TempoAccountsProvider {
    fn supports(&self, method: &str, intent: &str) -> bool {
        method == crate::protocol::methods::tempo::METHOD_NAME
            && (intent == crate::protocol::methods::tempo::INTENT_CHARGE
                || (intent == crate::protocol::methods::tempo::INTENT_SESSION
                    && self.session.is_some()))
    }

    async fn pay(&self, challenge: &PaymentChallenge) -> Result<PaymentCredential, MppError> {
        if challenge.intent.as_str() == crate::protocol::methods::tempo::INTENT_SESSION {
            return self.configured_session_provider()?.pay(challenge).await;
        }
        let from = self
            .wallet
            .active_account()
            .mpp_config("failed to read the active Tempo account")?;
        let charge = super::provider::prepare_charge_request(
            challenge,
            self.expected_chain_id,
            self.client_id.as_deref(),
        )?;
        let rpc_provider = super::rpc_provider(self.settlement_rpc_url(charge.chain_id())?);
        let charge =
            super::provider::apply_autoswap(charge, self.autoswap.as_ref(), &rpc_provider, from)
                .await?;

        let wallet = if charge.amount().is_zero() {
            self.wallet.clone()
        } else {
            let request = charge.accounts_request(from)?;
            match self
                .prepare_executable_wallet(&rpc_provider, &request, from, charge.chain_id())
                .await?
            {
                ExecutableAccountsWallet::Ready(wallet) => wallet,
                ExecutableAccountsWallet::Rejected(error) => return Err(error),
            }
        };

        let signed = charge
            .sign_with_accounts_provider_options(
                &wallet,
                &rpc_provider,
                from,
                SignOptions {
                    fee_token: self.fee_token(),
                    ..Default::default()
                },
            )
            .await?;
        let reservation = signed.authorization_reservation();
        let credential = signed.into_credential();
        if let Some(reservation) = reservation {
            if let Err(error) = self.remember_authorization(&challenge.id, reservation) {
                let _ = self.wallet.release_authorization(reservation);
                return Err(error);
            }
        }
        Ok(credential)
    }

    async fn pay_with_context(
        &self,
        challenge: &PaymentChallenge,
        context: PaymentContext,
    ) -> Result<PaymentCredential, MppError> {
        if challenge.intent.as_str() == crate::protocol::methods::tempo::INTENT_SESSION {
            return self
                .configured_session_provider()?
                .pay_with_context(challenge, context)
                .await;
        }
        self.pay(challenge).await
    }

    async fn commit_payment(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<(), MppError> {
        if challenge.intent.as_str() == crate::protocol::methods::tempo::INTENT_SESSION {
            return self
                .configured_session_provider()?
                .commit_payment(challenge, credential)
                .await;
        }
        let _ = self.take_authorization(challenge, credential)?;
        Ok(())
    }

    async fn rollback_payment(
        &self,
        challenge: &PaymentChallenge,
        credential: &PaymentCredential,
    ) -> Result<(), MppError> {
        if challenge.intent.as_str() == crate::protocol::methods::tempo::INTENT_SESSION {
            return self
                .configured_session_provider()?
                .rollback_payment(challenge, credential)
                .await;
        }
        if let Some(reservation) = self.take_authorization(challenge, credential)? {
            self.wallet
                .release_authorization(reservation)
                .mpp_config("failed to release Tempo key authorization")?;
        }
        Ok(())
    }

    fn abandon_payment(&self, challenge: &PaymentChallenge, credential: &PaymentCredential) {
        if challenge.intent.as_str() == "session" {
            if let Ok(provider) = self.configured_session_provider() {
                provider.abandon_payment(challenge, credential);
            }
        }
    }

    fn accept_payment_header(&self) -> Option<String> {
        self.session
            .as_ref()
            .map(|_| "tempo/session, tempo/charge;q=0.5".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc, Mutex,
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    use alloy::{
        eips::eip2718::Decodable2718,
        network::NetworkWallet,
        primitives::Address,
        rpc::types::TransactionRequest,
        signers::{local::PrivateKeySigner, Signer},
        sol_types::SolCall,
    };
    use axum::{routing::post, Json, Router};
    use tempo_alloy::primitives::{
        transaction::{
            KeyAuthorization, KeychainVersion, PrimitiveSignature, SignatureType, TempoSignature,
        },
        AASigned,
    };

    use super::*;
    use crate::protocol::core::Base64UrlJson;
    use tempo_alloy::contracts::precompiles::ITIP20;
    use tempo_alloy::rpc::TempoTransactionRequest;

    static NEXT_STORE_ID: AtomicU64 = AtomicU64::new(0);

    struct TestRpc {
        url: reqwest::Url,
        seen_keys: Arc<Mutex<Vec<String>>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl TestRpc {
        async fn start(rejected_key: Option<Address>) -> Self {
            let seen_keys = Arc::new(Mutex::new(Vec::new()));
            let handler_seen_keys = seen_keys.clone();
            let app = Router::new().route(
                "/",
                post(move |Json(request): Json<serde_json::Value>| {
                    let seen_keys = handler_seen_keys.clone();
                    async move {
                        let id = request["id"].clone();
                        let key = request["params"][0]["keyId"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned();
                        seen_keys.lock().unwrap().push(key.clone());
                        let rejected = rejected_key.is_some_and(|candidate| {
                            key.eq_ignore_ascii_case(&candidate.to_string())
                        });
                        if rejected {
                            Json(serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "error": {
                                    "code": 3,
                                    "message": "execution reverted: SpendingLimitExceeded",
                                    "data": "0x8a9e71ea",
                                },
                            }))
                        } else {
                            Json(serde_json::json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": "0x",
                            }))
                        }
                    }
                }),
            );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            Self {
                url: format!("http://{address}/").parse().unwrap(),
                seen_keys,
                task,
            }
        }
    }

    impl Drop for TestRpc {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn provider() -> (TempoAccountsProvider, std::path::PathBuf, Address) {
        let private_key = "0x1234567890123456789012345678901234567890123456789012345678901234";
        let signer = private_key.parse::<PrivateKeySigner>().unwrap();
        let account = Address::repeat_byte(0x11);
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_STORE_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "mpp-tempo-accounts-{}-{unique}-{sequence}.json",
            std::process::id()
        ));
        let store = serde_json::json!({
            "tempo-cli.store": {
                "state": {
                    "activeAccount": 0,
                    "chainId": 4217,
                    "accounts": [{"address": account}],
                    "accessKeys": [{
                        "access": account,
                        "address": signer.address(),
                        "chainId": 4217,
                        "keyType": "secp256k1",
                        "privateKey": private_key,
                    }],
                },
            },
        });
        std::fs::write(&path, serde_json::to_vec(&store).unwrap()).unwrap();
        let provider = TempoAccountsProvider::from_store(&path).unwrap();
        (provider, path, account)
    }

    #[test]
    fn builds_session_provider_from_the_same_accounts_key() {
        let (provider, path, _) = provider();
        let swap_token = Address::repeat_byte(0x33);
        let provider = provider
            .with_expected_chain_id(4217)
            .with_autoswap(AutoswapConfig::new(swap_token, 100));
        let expected_key = provider.wallet().active_access_key().unwrap().address();
        let provider = provider
            .with_session_store(Arc::new(
                super::super::session::store::MemoryChannelStore::default(),
            ))
            .with_session_default_deposit(20_000)
            .with_session_top_up_amount(20_000)
            .with_session_max_deposit(1_000_000);
        assert_eq!(
            provider.session.as_ref().unwrap().top_up_amount,
            Some(20_000)
        );
        let session = provider.configured_session_provider().unwrap();

        assert!(provider.supports("tempo", "charge"));
        assert!(provider.supports("tempo", "session"));
        assert_eq!(
            provider.accept_payment_header().as_deref(),
            Some("tempo/session, tempo/charge;q=0.5")
        );
        assert!(session.supports("tempo", "session"));
        assert_eq!(session.signer().address(), expected_key);
        assert_eq!(session.autoswap().unwrap().token_in, swap_token);
        std::fs::remove_file(path).unwrap();
    }

    fn challenge(amount: &str, fee_payer: bool) -> PaymentChallenge {
        let request = Base64UrlJson::from_value(&serde_json::json!({
            "amount": amount,
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": {"chainId": 4217, "feePayer": fee_payer},
        }))
        .unwrap();
        PaymentChallenge::new(
            "challenge-123",
            "api.example.com",
            "tempo",
            "charge",
            request,
        )
    }

    fn assert_accounts_signature(signed: &AASigned, account: Address, key: Address) {
        let TempoSignature::Keychain(signature) = signed.signature() else {
            panic!("expected an Accounts keychain signature")
        };
        assert_eq!(signature.user_address, account);
        assert_eq!(signature.version, KeychainVersion::V2);
        assert_eq!(
            signature.key_id(&signed.tx().signature_hash()).unwrap(),
            key
        );
    }

    #[tokio::test]
    async fn zero_charge_uses_the_accounts_key_without_a_signing_mode() {
        let (provider, path, account) = provider();
        let credential = provider.pay(&challenge("0", false)).await.unwrap();

        assert!(credential.charge_payload().unwrap().is_proof());
        assert_eq!(
            credential.source,
            Some(PaymentCredential::evm_did(4217, &account.to_string()))
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn zero_charge_selects_the_key_on_the_challenge_chain() {
        let (provider, path, _) = provider();
        let mut other_chain = challenge("0", false);
        other_chain.request = Base64UrlJson::from_value(&serde_json::json!({
            "amount": "0",
            "currency": "0x20c0000000000000000000000000000000000000",
            "recipient": "0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2",
            "methodDetails": {"chainId": 42431},
        }))
        .unwrap();

        let error = provider.pay(&other_chain).await.unwrap_err();
        assert!(error.to_string().contains("42431"), "got: {error}");
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn challenge_preflight_checks_the_transfer_scope() {
        let (provider, path, _) = provider();
        let rpc = TestRpc::start(None).await;
        let provider = provider.with_rpc_url(rpc.url.clone());
        let mut store: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        store["tempo-cli.store"]["state"]["accessKeys"][0]["scopes"] = serde_json::json!([{
            "address": "0x20c0000000000000000000000000000000000000",
            "selector": alloy::hex::encode_prefixed(ITIP20::transferWithMemoCall::SELECTOR),
            "recipients": ["0x0000000000000000000000000000000000000001"],
        }]);
        std::fs::write(&path, serde_json::to_vec(&store).unwrap()).unwrap();

        assert!(!provider
            .has_access_key_for_challenge(&challenge("100", false))
            .await
            .unwrap());

        store["tempo-cli.store"]["state"]["accessKeys"][0]["scopes"][0]["recipients"] =
            serde_json::json!(["0x742d35Cc6634C0532925a3b844Bc9e7595f1B0F2"]);
        std::fs::write(&path, serde_json::to_vec(&store).unwrap()).unwrap();
        assert!(provider
            .has_access_key_for_challenge(&challenge("100", false))
            .await
            .unwrap());
        assert_eq!(rpc.seen_keys.lock().unwrap().len(), 1);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn depleted_key_falls_through_to_an_executable_key() {
        let (provider, path, account) = provider();
        let depleted = provider.wallet().active_access_key().unwrap().address();
        let replacement_private_key = format!("0x{}", "22".repeat(32));
        let replacement = replacement_private_key.parse::<PrivateKeySigner>().unwrap();
        let mut store: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        store["tempo-cli.store"]["state"]["accessKeys"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "access": account,
                "address": replacement.address(),
                "chainId": 4217,
                "keyType": "secp256k1",
                "privateKey": replacement_private_key,
            }));
        std::fs::write(&path, serde_json::to_vec(&store).unwrap()).unwrap();

        let rpc = TestRpc::start(Some(depleted)).await;
        let provider = provider.with_rpc_url(rpc.url.clone());
        let credential = provider.pay(&challenge("100", true)).await.unwrap();
        let encoded = alloy::hex::decode(
            credential
                .charge_payload()
                .unwrap()
                .signed_tx()
                .unwrap()
                .trim_start_matches("0x"),
        )
        .unwrap();
        let envelope =
            crate::protocol::methods::tempo::FeePayerEnvelope78::decode_envelope(&encoded).unwrap();
        assert_accounts_signature(
            &envelope.to_recoverable_signed(),
            account,
            replacement.address(),
        );
        assert_eq!(
            *rpc.seen_keys.lock().unwrap(),
            vec![
                format!("{depleted:#x}"),
                format!("{:#x}", replacement.address())
            ]
        );
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn rejected_payment_releases_its_one_time_authorization() {
        let root = PrivateKeySigner::random();
        let account = root.address();
        let signer = PrivateKeySigner::random();
        let authorization =
            KeyAuthorization::unrestricted(4217, SignatureType::Secp256k1, signer.address());
        let signature = root
            .sign_hash(&authorization.signature_hash())
            .await
            .unwrap();
        let authorization = authorization.into_signed(PrimitiveSignature::Secp256k1(signature));
        let wallet = TempoAccountsWallet::from_secp256k1(account, signer, Some(authorization))
            .with_chain_id(4217);
        let provider = TempoAccountsProvider::new(wallet.clone());
        let request = TempoTransactionRequest {
            inner: TransactionRequest {
                to: Some(Address::repeat_byte(0x22).into()),
                nonce: Some(0),
                gas: Some(100_000),
                max_fee_per_gas: Some(1),
                max_priority_fee_per_gas: Some(1),
                ..Default::default()
            },
            ..Default::default()
        };
        wallet.sign_request(request.clone()).await.unwrap();
        let reservation = wallet.authorization_reservation().unwrap();
        provider
            .remember_authorization("challenge-123", reservation)
            .unwrap();
        let challenge = challenge("100", false);
        let credential =
            PaymentCredential::new(challenge.to_echo(), serde_json::json!({"test": true}));

        provider
            .rollback_payment(&challenge, &credential)
            .await
            .unwrap();
        wallet.sign_request(request).await.unwrap();
        wallet.release_authorization(reservation).unwrap();
    }

    #[tokio::test]
    async fn accounts_key_signs_a_standard_alloy_tempo_envelope() {
        let (provider, path, account) = provider();
        let key = provider.wallet().active_access_key().unwrap().address();
        let charge =
            super::super::charge::TempoCharge::from_challenge(&challenge("100", false)).unwrap();
        let rpc_provider = super::super::rpc_provider("https://rpc.example.com".parse().unwrap());
        let signed = charge
            .sign_with_accounts_provider_options(
                provider.wallet(),
                &rpc_provider,
                account,
                SignOptions {
                    gas_limit: Some(200_000),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let mut encoded = signed.tx_bytes();
        let decoded = AASigned::decode_2718(&mut encoded).unwrap();
        assert_eq!(decoded.tx().chain_id, 4217);
        assert_eq!(decoded.tx().gas_limit, 200_000);
        assert_eq!(
            decoded.tx().fee_token,
            Some(
                "0x20c0000000000000000000000000000000000000"
                    .parse()
                    .unwrap()
            )
        );
        assert!(decoded.tx().fee_payer_signature.is_none());
        assert_accounts_signature(&decoded, account, key);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn settlement_rpc_follows_the_charge_chain() {
        let (provider, path, _) = provider();
        assert_eq!(
            provider.settlement_rpc_url(4217).unwrap().as_str(),
            "https://rpc.tempo.xyz/"
        );
        assert_eq!(
            provider.settlement_rpc_url(42431).unwrap().as_str(),
            "https://rpc.moderato.tempo.xyz/"
        );
        assert!(provider.settlement_rpc_url(1).is_err());
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn accounts_key_signs_a_sponsored_charge_without_a_signing_mode() {
        let (provider, path, account) = provider();
        let rpc = TestRpc::start(None).await;
        let provider = provider.with_rpc_url(rpc.url.clone());
        let key = provider.wallet().active_access_key().unwrap().address();
        let credential = provider.pay(&challenge("100", true)).await.unwrap();

        let payload = credential.charge_payload().unwrap();
        assert!(payload.is_transaction());
        let encoded =
            alloy::hex::decode(payload.signed_tx().unwrap().trim_start_matches("0x")).unwrap();
        let envelope =
            crate::protocol::methods::tempo::FeePayerEnvelope78::decode_envelope(&encoded).unwrap();
        assert_eq!(envelope.chain_id, 4217);
        assert_eq!(envelope.sender, account);
        assert_eq!(envelope.nonce_key, alloy::primitives::U256::MAX);
        assert!(envelope.valid_before.is_some());
        assert!(envelope.fee_token.is_none());
        assert_accounts_signature(&envelope.to_recoverable_signed(), account, key);
        assert_eq!(
            credential.source,
            Some(PaymentCredential::evm_did(4217, &account.to_string()))
        );
        std::fs::remove_file(path).unwrap();
    }
}
