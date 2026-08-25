// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use primp::{Impersonate, ImpersonateOS};
use rand::RngExt;
use serde::Deserialize;

#[derive(Clone, Debug)]
pub struct Profile {
    pub impersonate: Impersonate,
    pub os: ImpersonateOS,
    pub user_agent: String,
    pub sec_ch_ua: String,
    pub sec_ch_ua_mobile: String,
    pub sec_ch_ua_platform: String,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            impersonate: Impersonate::Chrome,
            os: ImpersonateOS::Windows,
            user_agent: String::new(),
            sec_ch_ua: String::new(),
            sec_ch_ua_mobile: String::new(),
            sec_ch_ua_platform: String::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct SavedProfile {
    #[serde(default)]
    #[allow(dead_code)]
    pub user_agent: String,
    pub device_json: String,
    pub browser_fp: String,
}

pub fn load_saved_profile() -> Option<SavedProfile> {
    let data = std::fs::read("vk_profile.json").ok()?;
    serde_json::from_slice(&data).ok()
}

struct WeightedProfile {
    impersonate: Impersonate,
    os: ImpersonateOS,
    weight: u32,
}

fn wp(impersonate: Impersonate, os: ImpersonateOS, weight: u32) -> WeightedProfile {
    WeightedProfile {
        impersonate,
        os,
        weight,
    }
}

fn pick_weighted(pool: &[WeightedProfile]) -> (Impersonate, ImpersonateOS) {
    let total: u32 = pool.iter().map(|entry| entry.weight).sum();
    let mut roll = rand::rng().random_range(0..total);
    for entry in pool {
        if roll < entry.weight {
            return (entry.impersonate, entry.os);
        }
        roll -= entry.weight;
    }
    let last = &pool[pool.len() - 1];
    (last.impersonate, last.os)
}

fn chrome_pool() -> Vec<WeightedProfile> {
    vec![
        wp(Impersonate::ChromeV148, ImpersonateOS::Windows, 25),
        wp(Impersonate::ChromeV148, ImpersonateOS::MacOS, 12),
        wp(Impersonate::ChromeV148, ImpersonateOS::Linux, 5),
        wp(Impersonate::ChromeV147, ImpersonateOS::Windows, 18),
        wp(Impersonate::ChromeV147, ImpersonateOS::MacOS, 8),
        wp(Impersonate::ChromeV147, ImpersonateOS::Linux, 3),
        wp(Impersonate::ChromeV146, ImpersonateOS::Windows, 10),
        wp(Impersonate::ChromeV146, ImpersonateOS::MacOS, 5),
        wp(Impersonate::ChromeV146, ImpersonateOS::Linux, 2),
        wp(Impersonate::ChromeV145, ImpersonateOS::Windows, 5),
        wp(Impersonate::ChromeV145, ImpersonateOS::MacOS, 3),
        wp(Impersonate::ChromeV145, ImpersonateOS::Linux, 1),
        wp(Impersonate::ChromeV144, ImpersonateOS::Windows, 2),
        wp(Impersonate::ChromeV144, ImpersonateOS::MacOS, 1),
    ]
}

fn firefox_pool() -> Vec<WeightedProfile> {
    vec![
        wp(Impersonate::FirefoxV148, ImpersonateOS::Windows, 20),
        wp(Impersonate::FirefoxV148, ImpersonateOS::MacOS, 8),
        wp(Impersonate::FirefoxV148, ImpersonateOS::Linux, 10),
        wp(Impersonate::FirefoxV147, ImpersonateOS::Windows, 14),
        wp(Impersonate::FirefoxV147, ImpersonateOS::MacOS, 6),
        wp(Impersonate::FirefoxV147, ImpersonateOS::Linux, 8),
        wp(Impersonate::FirefoxV146, ImpersonateOS::Windows, 8),
        wp(Impersonate::FirefoxV146, ImpersonateOS::MacOS, 4),
        wp(Impersonate::FirefoxV146, ImpersonateOS::Linux, 6),
        wp(Impersonate::FirefoxV140, ImpersonateOS::Windows, 5),
        wp(Impersonate::FirefoxV140, ImpersonateOS::MacOS, 3),
        wp(Impersonate::FirefoxV140, ImpersonateOS::Linux, 8),
    ]
}

fn safari_pool() -> Vec<WeightedProfile> {
    vec![
        wp(Impersonate::SafariV26_3, ImpersonateOS::MacOS, 40),
        wp(Impersonate::SafariV26, ImpersonateOS::MacOS, 35),
        wp(Impersonate::SafariV18_5, ImpersonateOS::MacOS, 25),
    ]
}

pub fn random_profile(fingerprint: &str) -> Profile {
    let (impersonate, os) = match fingerprint {
        "safari" => pick_weighted(&safari_pool()),
        "firefox" => pick_weighted(&firefox_pool()),
        _ => pick_weighted(&chrome_pool()),
    };
    Profile {
        impersonate,
        os,
        user_agent: String::new(),
        sec_ch_ua: String::new(),
        sec_ch_ua_mobile: String::new(),
        sec_ch_ua_platform: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn saved_profile_accepts_go_partial_json() {
        let saved: SavedProfile =
            serde_json::from_str(r#"{"device_json":"{}","browser_fp":"0123456789abcdef"}"#)
                .unwrap();
        assert_eq!(saved.device_json, "{}");
        assert_eq!(saved.browser_fp, "0123456789abcdef");
        assert!(saved.user_agent.is_empty());
    }

    #[test]
    fn chrome_profiles_produce_diverse_versions_and_os_combinations() {
        let mut seen = HashSet::new();
        for _ in 0..200 {
            let profile = random_profile("chrome");
            seen.insert(format!("{:?}/{:?}", profile.impersonate, profile.os));
        }
        assert!(
            seen.len() >= 8,
            "Chrome diversity too low: only {} unique profiles: {:?}",
            seen.len(),
            seen
        );
    }

    #[test]
    fn firefox_profiles_produce_diverse_combinations() {
        let mut seen = HashSet::new();
        for _ in 0..200 {
            let profile = random_profile("firefox");
            seen.insert(format!("{:?}/{:?}", profile.impersonate, profile.os));
        }
        assert!(
            seen.len() >= 6,
            "Firefox diversity too low: only {} unique profiles: {:?}",
            seen.len(),
            seen
        );
    }

    #[test]
    fn safari_profiles_are_always_macos() {
        for _ in 0..100 {
            let profile = random_profile("safari");
            assert_eq!(profile.os, ImpersonateOS::MacOS);
        }
    }

    #[test]
    fn default_fingerprint_is_chrome() {
        let profile = random_profile("anything");
        let name = format!("{:?}", profile.impersonate);
        assert!(
            name.contains("Chrome"),
            "Default fingerprint should be Chrome, got {name}"
        );
    }
}
