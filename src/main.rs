use std::sync::Arc;
use std::time::Instant;
use crate::shared::{BenchmarkParam, ResumptionParam};

mod shared {
    #[derive(PartialEq, Clone, Copy)]
    pub enum ClientAuth {
        No,
        Yes,
    }

    #[derive(PartialEq, Clone, Copy)]
    pub enum ResumptionParam {
        No,
        SessionID,
        Tickets,
    }

    impl ResumptionParam {
        pub fn label(&self) -> &'static str {
            match *self {
                Self::No => "no-resume",
                Self::SessionID => "sessionid",
                Self::Tickets => "tickets",
            }
        }
    }

    // copied from tests/api.rs
    #[derive(PartialEq, Clone, Copy, Debug)]
    pub enum KeyType {
        Rsa,
        Ecdsa,
        Ed25519,
    }

    impl KeyType {
        pub fn path_for(&self, part: &str) -> String {
            match self {
                Self::Rsa => format!("test-ca/rsa/{}", part),
                Self::Ecdsa => format!("test-ca/ecdsa/{}", part),
                Self::Ed25519 => format!("test-ca/eddsa/{}", part),
            }
        }
    }

    pub struct BenchmarkParam<TSupportedCipherSuite, TSupportedProtocolVersion: 'static> {
        pub key_type: KeyType,
        pub ciphersuite: TSupportedCipherSuite,
        pub version: &'static TSupportedProtocolVersion,
    }

    impl<TSupportedCipherSuite, TSupportedProtocolVersion> BenchmarkParam<TSupportedCipherSuite, TSupportedProtocolVersion> {
        pub const fn new(
            key_type: KeyType,
            ciphersuite: TSupportedCipherSuite,
            version: &'static TSupportedProtocolVersion,
        ) -> Self {
            Self {
                key_type,
                ciphersuite,
                version,
            }
        }
    }
}

mod baseline {
    use std::io::Read;
    use std::ops::{Deref, DerefMut};
    use std::sync::Arc;
    use std::{fs, io};
    use rustls_baseline::{Certificate, ClientConfig, ClientConnection, ConnectionCommon, PrivateKey, RootCertStore, ServerConfig, ServerConnection, SideData, SupportedCipherSuite, SupportedProtocolVersion, Ticketer};
    use rustls_baseline::client::Resumption;
    use rustls_baseline::server::{AllowAnyAuthenticatedClient, NoClientAuth, NoServerSessionStorage, ServerSessionMemoryCache};
    use crate::shared::{BenchmarkParam, ClientAuth, KeyType, ResumptionParam};

    fn get_chain(key_type: KeyType) -> Vec<Certificate> {
        rustls_pemfile::certs(&mut io::BufReader::new(
            fs::File::open(key_type.path_for("end.fullchain")).unwrap(),
        ))
            .unwrap()
            .iter()
            .map(|v| Certificate(v.clone()))
            .collect()
    }

    fn get_key(key_type: KeyType) -> PrivateKey {
        PrivateKey(
            rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(
                fs::File::open(key_type.path_for("end.key")).unwrap(),
            ))
                .unwrap()[0]
                .clone(),
        )
    }

    fn get_client_chain(key_type: KeyType) -> Vec<Certificate> {
        rustls_pemfile::certs(&mut io::BufReader::new(
            fs::File::open(key_type.path_for("client.fullchain")).unwrap(),
        ))
            .unwrap()
            .iter()
            .map(|v| Certificate(v.clone()))
            .collect()
    }

    fn get_client_key(key_type: KeyType) -> PrivateKey {
        PrivateKey(
            rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(
                fs::File::open(key_type.path_for("client.key")).unwrap(),
            ))
                .unwrap()[0]
                .clone(),
        )
    }

    pub fn make_client_config(
        params: &BenchmarkParam<SupportedCipherSuite, SupportedProtocolVersion>,
        clientauth: ClientAuth,
        resume: ResumptionParam,
    ) -> ClientConfig {
        let mut root_store = RootCertStore::empty();
        let mut rootbuf =
            std::io::BufReader::new(std::fs::File::open(params.key_type.path_for("ca.cert")).unwrap());
        root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut rootbuf).unwrap());

        let cfg = ClientConfig::builder()
            .with_cipher_suites(&[params.ciphersuite])
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[params.version])
            .unwrap()
            .with_root_certificates(root_store);

        let mut cfg = if clientauth == ClientAuth::Yes {
            unimplemented!()
            // cfg.with_client_auth_cert(
            //     get_client_chain(params.key_type),
            //     get_client_key(params.key_type),
            // )
            //     .unwrap()
        } else {
            cfg.with_no_client_auth()
        };

        if resume != ResumptionParam::No {
            cfg.resumption = Resumption::in_memory_sessions(128);
        } else {
            cfg.resumption = Resumption::disabled();
        }

        cfg
    }

    pub fn make_server_config(
        params: &BenchmarkParam<SupportedCipherSuite, SupportedProtocolVersion>,
        client_auth: ClientAuth,
        resume: ResumptionParam,
        max_fragment_size: Option<usize>,
    ) -> ServerConfig {
        let client_auth = match client_auth {
            ClientAuth::Yes => {
                let roots = get_chain(params.key_type);
                let mut client_auth_roots = RootCertStore::empty();
                for root in roots {
                    client_auth_roots.add(&root).unwrap();
                }
                Arc::new(AllowAnyAuthenticatedClient::new(client_auth_roots))
            }
            ClientAuth::No => NoClientAuth::boxed(),
        };

        let mut cfg = ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[params.version])
            .unwrap()
            .with_client_cert_verifier(client_auth)
            .with_single_cert(get_chain(params.key_type), get_key(params.key_type))
            .expect("bad certs/private key?");

        if resume == ResumptionParam::SessionID {
            cfg.session_storage = ServerSessionMemoryCache::new(128);
        } else if resume == ResumptionParam::Tickets {
            cfg.ticketer = Ticketer::new().unwrap();
        } else {
            cfg.session_storage = Arc::new(NoServerSessionStorage {});
        }

        cfg.max_fragment_size = max_fragment_size;
        cfg
    }

    pub fn bench_handshake(client_config: Arc<ClientConfig>, server_config: Arc<ServerConfig>) {
        let server_name = "localhost".try_into().unwrap();
        let mut client = ClientConnection::new(Arc::clone(&client_config), server_name).unwrap();
        let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

        transfer(&mut client, &mut server, None);
        transfer(&mut server, &mut client, None);
        transfer(&mut client, &mut server, None);
        transfer(&mut server, &mut client, None);
    }

    fn transfer<L, R, LS, RS>(left: &mut L, right: &mut R, expect_data: Option<usize>)
        where
            L: DerefMut + Deref<Target = ConnectionCommon<LS>>,
            R: DerefMut + Deref<Target = ConnectionCommon<RS>>,
            LS: SideData,
            RS: SideData,
    {
        let mut tls_buf = [0u8; 262144];
        let mut data_left = expect_data;
        let mut data_buf = [0u8; 8192];

        loop {
            let mut sz = 0;

            while left.wants_write() {
                let written = left
                    .write_tls(&mut tls_buf[sz..].as_mut())
                    .unwrap();
                if written == 0 {
                    break;
                }

                sz += written;
            }

            if sz == 0 {
                return;
            }

            let mut offs = 0;
            loop {
                match right.read_tls(&mut tls_buf[offs..sz].as_ref()) {
                    Ok(read) => {
                        right.process_new_packets().unwrap();
                        offs += read;
                    }
                    Err(err) => {
                        panic!("error on transfer {}..{}: {}", offs, sz, err);
                    }
                }

                if let Some(left) = &mut data_left {
                    loop {
                        let sz = match right.reader().read(&mut data_buf) {
                            Ok(sz) => sz,
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(err) => panic!("failed to read data: {}", err),
                        };

                        *left -= sz;
                        if *left == 0 {
                            break;
                        }
                    }
                }

                if sz == offs {
                    break;
                }
            }
        }
    }
}

mod candidate {
    use std::{fs, io};
    use std::io::Read;
    use std::ops::{Deref, DerefMut};
    use std::sync::Arc;
    use rustls_candidate::{Certificate, ClientConfig, ClientConnection, ConnectionCommon, PrivateKey, RootCertStore, ServerConfig, ServerConnection, SideData, SupportedCipherSuite, SupportedProtocolVersion, Ticketer};
    use rustls_candidate::client::Resumption;
    use rustls_candidate::server::{AllowAnyAuthenticatedClient, NoClientAuth, NoServerSessionStorage, ServerSessionMemoryCache};
    use crate::shared::{BenchmarkParam, ClientAuth, KeyType, ResumptionParam};

    fn get_chain(key_type: KeyType) -> Vec<Certificate> {
        rustls_pemfile::certs(&mut io::BufReader::new(
            fs::File::open(key_type.path_for("end.fullchain")).unwrap(),
        ))
            .unwrap()
            .iter()
            .map(|v| Certificate(v.clone()))
            .collect()
    }

    fn get_key(key_type: KeyType) -> PrivateKey {
        PrivateKey(
            rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(
                fs::File::open(key_type.path_for("end.key")).unwrap(),
            ))
                .unwrap()[0]
                .clone(),
        )
    }

    fn get_client_chain(key_type: KeyType) -> Vec<Certificate> {
        rustls_pemfile::certs(&mut io::BufReader::new(
            fs::File::open(key_type.path_for("client.fullchain")).unwrap(),
        ))
            .unwrap()
            .iter()
            .map(|v| Certificate(v.clone()))
            .collect()
    }

    fn get_client_key(key_type: KeyType) -> PrivateKey {
        PrivateKey(
            rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(
                fs::File::open(key_type.path_for("client.key")).unwrap(),
            ))
                .unwrap()[0]
                .clone(),
        )
    }

    pub fn make_client_config(
        params: &BenchmarkParam<SupportedCipherSuite, SupportedProtocolVersion>,
        clientauth: ClientAuth,
        resume: ResumptionParam,
    ) -> ClientConfig {
        let mut root_store = RootCertStore::empty();
        let mut rootbuf =
            std::io::BufReader::new(std::fs::File::open(params.key_type.path_for("ca.cert")).unwrap());
        root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut rootbuf).unwrap());

        let cfg = ClientConfig::builder()
            .with_cipher_suites(&[params.ciphersuite])
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[params.version])
            .unwrap()
            .with_root_certificates(root_store);

        let mut cfg = if clientauth == ClientAuth::Yes {
            cfg.with_client_auth_cert(
                get_client_chain(params.key_type),
                get_client_key(params.key_type),
            )
                .unwrap()
        } else {
            cfg.with_no_client_auth()
        };

        if resume != ResumptionParam::No {
            cfg.resumption = Resumption::in_memory_sessions(128);
        } else {
            cfg.resumption = Resumption::disabled();
        }

        cfg
    }

    pub fn make_server_config(
        params: &BenchmarkParam<SupportedCipherSuite, SupportedProtocolVersion>,
        client_auth: ClientAuth,
        resume: ResumptionParam,
        max_fragment_size: Option<usize>,
    ) -> ServerConfig {
        let client_auth = match client_auth {
            ClientAuth::Yes => {
                let roots = get_chain(params.key_type);
                let mut client_auth_roots = RootCertStore::empty();
                for root in roots {
                    client_auth_roots.add(&root).unwrap();
                }
                Arc::new(AllowAnyAuthenticatedClient::new(client_auth_roots))
            }
            ClientAuth::No => NoClientAuth::boxed(),
        };

        let mut cfg = ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[params.version])
            .unwrap()
            .with_client_cert_verifier(client_auth)
            .with_single_cert(get_chain(params.key_type), get_key(params.key_type))
            .expect("bad certs/private key?");

        if resume == ResumptionParam::SessionID {
            cfg.session_storage = ServerSessionMemoryCache::new(128);
        } else if resume == ResumptionParam::Tickets {
            cfg.ticketer = Ticketer::new().unwrap();
        } else {
            cfg.session_storage = Arc::new(NoServerSessionStorage {});
        }

        cfg.max_fragment_size = max_fragment_size;
        cfg
    }

    pub fn bench_handshake(client_config: Arc<ClientConfig>, server_config: Arc<ServerConfig>) {
        let server_name = "localhost".try_into().unwrap();
        let mut client = ClientConnection::new(Arc::clone(&client_config), server_name).unwrap();
        let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

        transfer(&mut client, &mut server, None);
        transfer(&mut server, &mut client, None);
        transfer(&mut client, &mut server, None);
        transfer(&mut server, &mut client, None);
    }

    fn transfer<L, R, LS, RS>(left: &mut L, right: &mut R, expect_data: Option<usize>)
        where
            L: DerefMut + Deref<Target = ConnectionCommon<LS>>,
            R: DerefMut + Deref<Target = ConnectionCommon<RS>>,
            LS: SideData,
            RS: SideData,
    {
        let mut tls_buf = [0u8; 262144];
        let mut data_left = expect_data;
        let mut data_buf = [0u8; 8192];

        loop {
            let mut sz = 0;

            while left.wants_write() {
                let written = left
                    .write_tls(&mut tls_buf[sz..].as_mut())
                    .unwrap();
                if written == 0 {
                    break;
                }

                sz += written;
            }

            if sz == 0 {
                return;
            }

            let mut offs = 0;
            loop {
                match right.read_tls(&mut tls_buf[offs..sz].as_ref()) {
                    Ok(read) => {
                        right.process_new_packets().unwrap();
                        offs += read;
                    }
                    Err(err) => {
                        panic!("error on transfer {}..{}: {}", offs, sz, err);
                    }
                }

                if let Some(left) = &mut data_left {
                    loop {
                        let sz = match right.reader().read(&mut data_buf) {
                            Ok(sz) => sz,
                            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(err) => panic!("failed to read data: {}", err),
                        };

                        *left -= sz;
                        if *left == 0 {
                            break;
                        }
                    }
                }

                if sz == offs {
                    break;
                }
            }
        }
    }
}

struct BenchmarkScenario {
    baseline_params: BenchmarkParam<rustls_baseline::SupportedCipherSuite, rustls_baseline::SupportedProtocolVersion>,
    candidate_params: BenchmarkParam<rustls_candidate::SupportedCipherSuite, rustls_candidate::SupportedProtocolVersion>,
    client_auth: shared::ClientAuth,
    resumption: ResumptionParam,
}

fn main() {
    let bench_scenarios = [
        BenchmarkScenario {
            baseline_params: BenchmarkParam::new(
                shared::KeyType::Ecdsa,
                rustls_baseline::cipher_suite::TLS13_AES_128_GCM_SHA256,
                &rustls_baseline::version::TLS13,
            ),
            candidate_params: BenchmarkParam::new(
                shared::KeyType::Ecdsa,
                rustls_candidate::cipher_suite::TLS13_AES_128_GCM_SHA256,
                &rustls_candidate::version::TLS13,
            ),
            client_auth: shared::ClientAuth::No,
            resumption: ResumptionParam::No,
        },
        BenchmarkScenario {
            baseline_params: BenchmarkParam::new(
                shared::KeyType::Ecdsa,
                rustls_baseline::cipher_suite::TLS13_AES_128_GCM_SHA256,
                &rustls_baseline::version::TLS13,
            ),
            candidate_params: BenchmarkParam::new(
                shared::KeyType::Ecdsa,
                rustls_candidate::cipher_suite::TLS13_AES_128_GCM_SHA256,
                &rustls_candidate::version::TLS13,
            ),
            client_auth: shared::ClientAuth::No,
            resumption: ResumptionParam::Tickets,
        },
        BenchmarkScenario {
            baseline_params: BenchmarkParam::new(
                shared::KeyType::Ecdsa,
                rustls_baseline::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                &rustls_baseline::version::TLS12,
            ),
            candidate_params: BenchmarkParam::new(
                shared::KeyType::Ecdsa,
                rustls_candidate::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                &rustls_candidate::version::TLS12,
            ),
            client_auth: shared::ClientAuth::No,
            resumption: ResumptionParam::No,
        },
        BenchmarkScenario {
            baseline_params: BenchmarkParam::new(
                shared::KeyType::Ecdsa,
                rustls_baseline::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                &rustls_baseline::version::TLS12,
            ),
            candidate_params: BenchmarkParam::new(
                shared::KeyType::Ecdsa,
                rustls_candidate::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                &rustls_candidate::version::TLS12,
            ),
            client_auth: shared::ClientAuth::No,
            resumption: ResumptionParam::Tickets,
        },
    ];

    for scenario in bench_scenarios {
        run_benchmark(&scenario);
    }
}

fn run_benchmark(scenario: &BenchmarkScenario) {
    let baseline_client_config = Arc::new(baseline::make_client_config(&scenario.baseline_params, scenario.client_auth, scenario.resumption));
    let baseline_server_config = Arc::new(baseline::make_server_config(&scenario.baseline_params, scenario.client_auth, scenario.resumption, None));
    let candidate_client_config = Arc::new(candidate::make_client_config(&scenario.candidate_params, scenario.client_auth, scenario.resumption));
    let candidate_server_config = Arc::new(candidate::make_server_config(&scenario.candidate_params, scenario.client_auth, scenario.resumption, None));

    let runs = 200;
    let mut timings = Vec::with_capacity(200);

    let mut rng = fastrand::Rng::with_seed(42);
    for _ in 0..runs {
        if rng.bool() {
            let candidate_start = Instant::now();
            candidate::bench_handshake(candidate_client_config.clone(), candidate_server_config.clone());
            let candidate_end_baseline_start = Instant::now();
            baseline::bench_handshake(baseline_client_config.clone(), baseline_server_config.clone());
            let baseline_end = Instant::now();
            timings.push((baseline_end - candidate_end_baseline_start, candidate_end_baseline_start - candidate_start));
        } else {
            let baseline_start = Instant::now();
            baseline::bench_handshake(baseline_client_config.clone(), baseline_server_config.clone());
            let baseline_end_candidate_start = Instant::now();
            candidate::bench_handshake(candidate_client_config.clone(), candidate_server_config.clone());
            let candidate_end = Instant::now();
            timings.push((baseline_end_candidate_start - baseline_start, candidate_end - baseline_end_candidate_start));
        }
    }

    let mut diffs = timings.iter().map(|(baseline_duration, candidate_duration)| {
        let baseline_nanos = baseline_duration.as_nanos() as i128;
        let candidate_nanos = candidate_duration.as_nanos() as i128;
        candidate_nanos - baseline_nanos
    }).collect::<Vec<_>>();

    diffs.sort_unstable();

    let q25 = diffs[24];
    let q75 = diffs[74];
    let iqr = q75 - q25;
    let scaled_iqr = iqr * 3 / 2; // 1.5 iqr

    let outliers = diffs.iter().filter(|&&diff| diff < q25 - scaled_iqr || diff > q75 + scaled_iqr).count();
    let mean = diffs.iter().filter(|&&diff| diff >= q25 - scaled_iqr && diff <= q75 + scaled_iqr).sum::<i128>() / (diffs.len() - outliers) as i128;
    let baseline_min_micros = timings.iter().map(|(d1, _)| d1).min().unwrap().as_micros();
    let candidate_min_micros = timings.iter().map(|(_, d2)| d2).min().unwrap().as_micros();

    println!("Config:");
    println!("* Baseline: {:?} {:?} (key = {:?})", scenario.baseline_params.version, scenario.baseline_params.ciphersuite, scenario.baseline_params.key_type);
    println!("* Candidate: {:?} {:?} (key = {:?})", scenario.candidate_params.version, scenario.candidate_params.ciphersuite, scenario.candidate_params.key_type);
    println!("* Resumption = {}", scenario.resumption.label());
    println!("Results after {runs} runs:");
    println!("* Discarded outliers: {outliers}");
    println!("* Minimum runtime (baseline): {} (µs)", baseline_min_micros);
    println!("* Minimum runtime (candidate): {} (µs)", candidate_min_micros);

    let mean_micros = mean / 1000;
    if mean_micros.abs() <= 3 {
        println!("* Mean difference: <= 3 (µs)")
    } else {
        let change_percent = (mean_micros as f64 / baseline_min_micros as f64) * 100.0;

        let sign = if mean > 0 {
            "+"
        } else {
            ""
        };

        println!("* Mean difference: {} µs ({sign}{:.2}%)", mean_micros, change_percent)
    }

    println!();
}
