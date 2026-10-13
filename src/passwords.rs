//! Extraction of credentials and secrets from decoded FRITZ!Box configuration files.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{avm_cfg::parse_avm_cfg, markers::CrcState, ConfigBackup, FileContent};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InternetAccount {
    pub provider: String,
    pub username: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VoipAccount {
    pub name: String,
    pub username: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authname: Option<String>,
    pub registrar: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stunserver: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WifiNetwork {
    pub ssid: String,
    pub psk: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub band: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RouterUser {
    pub username: String,
    pub password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Tr069Config {
    pub acs_url: String,
    pub acs_username: String,
    pub acs_password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_request_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_request_password: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VpnConnection {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ip: Option<String>,
    pub preshared_key: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExtractedCredentials {
    pub model: String,
    pub internet: Vec<InternetAccount>,
    pub voip: Vec<VoipAccount>,
    pub wifi: Vec<WifiNetwork>,
    pub users: Vec<RouterUser>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tr069: Option<Tr069Config>,
    pub vpn: Vec<VpnConnection>,
}

impl ExtractedCredentials {
    /// Extracts all known credentials from a decrypted `ConfigBackup`.
    #[must_use]
    pub fn extract<S: CrcState>(config: &ConfigBackup<S>) -> Self {
        let mut result = Self {
            model: config.model().to_string(),
            ..Default::default()
        };

        for file in config.files() {
            if let FileContent::Plain(content) = &file.content {
                match file.name.as_str() {
                    "ar7.cfg" => {
                        let parsed = parse_avm_cfg(content);
                        result.extract_from_ar7(&parsed);
                    }
                    "voip.cfg" => {
                        let parsed = parse_avm_cfg(content);
                        result.extract_from_voip(&parsed);
                    }
                    "wlan.cfg" => {
                        let parsed = parse_avm_cfg(content);
                        result.extract_from_wlan(&parsed);
                    }
                    "user.cfg" => {
                        let parsed = parse_avm_cfg(content);
                        result.extract_from_user(&parsed);
                    }
                    "tr069.cfg" => {
                        let parsed = parse_avm_cfg(content);
                        result.extract_from_tr069(&parsed);
                    }
                    "vpn.cfg" => {
                        let parsed = parse_avm_cfg(content);
                        result.extract_from_vpn(&parsed);
                    }
                    _ => {}
                }
            }
        }

        result
    }

    fn extract_from_ar7(&mut self, val: &Value) {
        let ar7 = &val["ar7cfg"];
        let provider = ar7["active_provider"]
            .as_str()
            .unwrap_or_default()
            .to_string();

        // Targets (PPPoE Internet, etc.)
        if let Some(targets) = ar7["targets"].as_array() {
            for target in targets {
                let name = target
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let username = target
                    .get("local")
                    .and_then(|l| l.get("username"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let passwd = target
                    .get("local")
                    .and_then(|l| l.get("passwd"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();

                if !username.is_empty() || !passwd.is_empty() {
                    self.internet.push(InternetAccount {
                        provider: if provider.is_empty() {
                            name.to_string()
                        } else {
                            provider.clone()
                        },
                        username: username.to_string(),
                        password: passwd.to_string(),
                        mode: Some(name.to_string()),
                    });
                }
            }
        } else if let Some(target) = ar7["targets"].as_object() {
            let name = target
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let username = target
                .get("local")
                .and_then(|l| l.get("username"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let passwd = target
                .get("local")
                .and_then(|l| l.get("passwd"))
                .and_then(Value::as_str)
                .unwrap_or_default();

            if !username.is_empty() || !passwd.is_empty() {
                self.internet.push(InternetAccount {
                    provider: if provider.is_empty() {
                        name.to_string()
                    } else {
                        provider.clone()
                    },
                    username: username.to_string(),
                    password: passwd.to_string(),
                    mode: Some(name.to_string()),
                });
            }
        }

        // Serial / Mobile fallback
        let serial = &ar7["serialcfg"];
        let s_user = serial["username"].as_str().unwrap_or_default();
        let s_pass = serial["passwd"].as_str().unwrap_or_default();
        let s_prov = serial["provider"].as_str().unwrap_or_default();
        if !s_user.is_empty() || !s_pass.is_empty() {
            self.internet.push(InternetAccount {
                provider: format!("Mobile ({s_prov})"),
                username: s_user.to_string(),
                password: s_pass.to_string(),
                mode: Some("Mobile Serial".to_string()),
            });
        }
    }

    fn extract_from_voip(&mut self, val: &Value) {
        let voip = &val["voipcfg"];
        if let Some(map) = voip.as_object() {
            for (key, subval) in map {
                if key.starts_with("ua") {
                    let user = subval["username"].as_str().unwrap_or_default();
                    let pass = subval["passwd"].as_str().unwrap_or_default();
                    let reg = subval["registrar"].as_str().unwrap_or_default();
                    let auth = subval["authname"].as_str().unwrap_or_default();
                    let name = subval["name"].as_str().unwrap_or(key);
                    let stun = subval["stunserver"].as_str().unwrap_or_default();

                    if !user.is_empty() || !pass.is_empty() {
                        self.voip.push(VoipAccount {
                            name: name.to_string(),
                            username: user.to_string(),
                            password: pass.to_string(),
                            authname: if auth.is_empty() {
                                None
                            } else {
                                Some(auth.to_string())
                            },
                            registrar: reg.to_string(),
                            stunserver: if stun.is_empty() {
                                None
                            } else {
                                Some(stun.to_string())
                            },
                        });
                    }
                }
            }
        }
    }

    fn extract_from_wlan(&mut self, val: &Value) {
        let wlan = &val["wlancfg"];
        // Primary SSID
        let ssid = wlan["ssid"].as_str().unwrap_or_default();
        let psk = wlan["pskvalue"].as_str().unwrap_or_default();
        if !ssid.is_empty() || !psk.is_empty() {
            self.wifi.push(WifiNetwork {
                ssid: ssid.to_string(),
                psk: psk.to_string(),
                band: Some("2.4 GHz / Primary".to_string()),
                encryption: wlan["encryption"].as_i64().map(|e| e.to_string()),
            });
        }

        // Secondary SSID (e.g. 5 GHz)
        let ssid_scnd = wlan["ssid_scnd"].as_str().unwrap_or_default();
        let psk_scnd = wlan["pskvalue_scnd"].as_str().unwrap_or(psk);
        if !ssid_scnd.is_empty() && ssid_scnd != ssid {
            self.wifi.push(WifiNetwork {
                ssid: ssid_scnd.to_string(),
                psk: psk_scnd.to_string(),
                band: Some("5 GHz".to_string()),
                encryption: None,
            });
        }

        // Guest SSID
        let ssid_guest = wlan["guest_ssid"].as_str().unwrap_or_default();
        let psk_guest = wlan["guest_pskvalue"].as_str().unwrap_or_default();
        if !ssid_guest.is_empty() {
            self.wifi.push(WifiNetwork {
                ssid: ssid_guest.to_string(),
                psk: psk_guest.to_string(),
                band: Some("Guest".to_string()),
                encryption: None,
            });
        }
    }

    fn extract_from_user(&mut self, val: &Value) {
        let users = &val["users"];
        let mut list = Vec::new();
        if let Some(arr) = users.as_array() {
            list.extend(arr.iter());
        } else if users.is_object() {
            list.push(users);
        }

        for u in list {
            let name = u["username"].as_str().unwrap_or_default();
            let pass = u["password"].as_str().unwrap_or_default();
            let email = u["email"].as_str().unwrap_or_default();

            if !name.is_empty() {
                self.users.push(RouterUser {
                    username: name.to_string(),
                    password: pass.to_string(),
                    email: if email.is_empty() {
                        None
                    } else {
                        Some(email.to_string())
                    },
                });
            }
        }
    }

    fn extract_from_tr069(&mut self, val: &Value) {
        let mgmt = &val["tr069cfg"]["igd"]["managementserver"];
        if let Some(url) = mgmt["url"].as_str() {
            let user = mgmt["username"].as_str().unwrap_or_default();
            let pass = mgmt["password"].as_str().unwrap_or_default();
            let cr_user = mgmt["ConnectionRequestUsername"].as_str();
            let cr_pass = mgmt["ConnectionRequestPassword"].as_str();

            self.tr069 = Some(Tr069Config {
                acs_url: url.to_string(),
                acs_username: user.to_string(),
                acs_password: pass.to_string(),
                connection_request_username: cr_user.map(String::from),
                connection_request_password: cr_pass.map(String::from),
            });
        }
    }

    fn extract_from_vpn(&mut self, val: &Value) {
        let conns = &val["vpncfg"]["connections"];
        let mut list = Vec::new();
        if let Some(arr) = conns.as_array() {
            list.extend(arr.iter());
        } else if conns.is_object() {
            list.push(conns);
        }

        for c in list {
            let name = c["name"].as_str().unwrap_or_default();
            let key = c["key"].as_str().unwrap_or_default();
            let remote = c["remoteip"].as_str();

            if !name.is_empty() && !key.is_empty() {
                self.vpn.push(VpnConnection {
                    name: name.to_string(),
                    remote_ip: remote.map(String::from),
                    preshared_key: key.to_string(),
                });
            }
        }
    }

    /// Formats the credentials into a clean, human-readable terminal output.
    #[must_use]
    pub fn format_text(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();

        writeln!(out, "=== CREDENTIALS EXTRACTED FROM {} ===", self.model).unwrap();

        // 1. Internet / ISP
        writeln!(out, "\n[Internet / ISP Accounts]").unwrap();
        if self.internet.is_empty() {
            writeln!(out, "  (None found)").unwrap();
        } else {
            for acc in &self.internet {
                writeln!(
                    out,
                    "  Provider: {} | User: {} | Password: {}",
                    acc.provider, acc.username, acc.password
                )
                .unwrap();
            }
        }

        // 2. Wi-Fi
        writeln!(out, "\n[Wi-Fi Networks]").unwrap();
        if self.wifi.is_empty() {
            writeln!(out, "  (None found)").unwrap();
        } else {
            for net in &self.wifi {
                let band = net.band.as_deref().unwrap_or("Standard");
                writeln!(
                    out,
                    "  SSID: {} ({}) | WPA Key: {}",
                    net.ssid, band, net.psk
                )
                .unwrap();
            }
        }

        // 3. VoIP / Telefonia
        writeln!(out, "\n[VoIP / Telephony Accounts]").unwrap();
        if self.voip.is_empty() {
            writeln!(out, "  (None found)").unwrap();
        } else {
            for v in &self.voip {
                writeln!(
                    out,
                    "  Number/Name: {} | Registrar: {} | User: {} | Password: {}",
                    v.name, v.registrar, v.username, v.password
                )
                .unwrap();
            }
        }

        // 4. Web GUI / Router Users
        writeln!(out, "\n[Router Users / Web Admin]").unwrap();
        if self.users.is_empty() {
            writeln!(out, "  (None found)").unwrap();
        } else {
            for u in &self.users {
                writeln!(out, "  User: {} | Password: {}", u.username, u.password).unwrap();
            }
        }

        // 5. TR-069 Management
        if let Some(tr) = &self.tr069 {
            writeln!(out, "\n[TR-069 Auto-Configuration]").unwrap();
            writeln!(
                out,
                "  ACS Server: {} | User: {} | Password: {}",
                tr.acs_url, tr.acs_username, tr.acs_password
            )
            .unwrap();
        }

        // 6. VPN
        if !self.vpn.is_empty() {
            writeln!(out, "\n[VPN Connections]").unwrap();
            for vpn in &self.vpn {
                writeln!(out, "  Name: {} | PSK Key: {}", vpn.name, vpn.preshared_key).unwrap();
            }
        }

        out
    }
}
