use std::net::{Ipv4Addr, Ipv6Addr};

use tracing;

use hickory_server::{
    authority::MessageResponseBuilder,
    proto::{
        op::{Header, ResponseCode},
        rr::{
            rdata::{
                svcb::{Alpn, EchConfig, IpHint, SvcParamKey, SvcParamValue},
                HTTPS, SVCB,
            },
            RData, Record, RecordType,
        },
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};

pub struct EchoxyDnsHandler {
    pub ipv4s: Vec<Ipv4Addr>,
    pub ipv6s: Vec<Ipv6Addr>,
    pub echconfigs: Vec<Vec<u8>>,
}

#[async_trait::async_trait]
impl RequestHandler for EchoxyDnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handler: R,
    ) -> ResponseInfo {
        let mut header = Header::response_from_request(&request.header());

        let rdatas: Vec<RData> = match request.query().query_type() {
            RecordType::A => self
                .ipv4s
                .iter()
                .map(|ipv4| RData::A(ipv4.clone().into()))
                .collect(),

            RecordType::AAAA => self
                .ipv6s
                .iter()
                .map(|ipv6| RData::AAAA(ipv6.clone().into()))
                .collect(),
            RecordType::HTTPS => {
                self.echconfigs
                    .iter()
                    .map(|echconfig| {
                        let svc_params = vec![
                            // (SvcParamKey::Port, SvcParamValue::Port(443)),
                            (
                                SvcParamKey::Alpn,
                                SvcParamValue::Alpn(Alpn(vec![
                                    "http/1.1".to_string(),
                                    "h2".to_string(),
                                ])),
                            ),
                            (
                                SvcParamKey::Ipv4Hint,
                                SvcParamValue::Ipv4Hint(IpHint(
                                    self.ipv4s.iter().map(|ipv4| ipv4.clone().into()).collect(),
                                )),
                            ),
                            (
                                SvcParamKey::EchConfig,
                                SvcParamValue::EchConfig(EchConfig(echconfig.clone())),
                            ),
                            (
                                SvcParamKey::Ipv6Hint,
                                SvcParamValue::Ipv6Hint(IpHint(
                                    self.ipv6s.iter().map(|ipv6| ipv6.clone().into()).collect(),
                                )),
                            ),
                        ];
                        let svcb = SVCB::new(1, Default::default(), svc_params);
                        RData::HTTPS(HTTPS(svcb))
                    })
                    .collect()
            }
            _ => {
                tracing::warn!("unsupported query type: {:?}", request.query().query_type());
                return header.into();
            }
        };

        let answers: Vec<Record> = rdatas
            .into_iter()
            .map(|rdata| Record::from_rdata(request.query().name().into(), 60, rdata))
            .collect();
        let response = MessageResponseBuilder::from_message_request(request)
            .build(header, &answers, None, None, None);

        match response_handler.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("request failed: {}", e);
                header.set_response_code(ResponseCode::ServFail);
                header.into()
            }
        }
    }
}
