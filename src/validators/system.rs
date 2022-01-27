use regex::Regex;

lazy_static! {
    static ref REGISTRY: Regex =  Regex::new(
        &[
            r"(?mi)",
            r"((^[^\n]*?)",
            r"((^\\?|\\)(HK(EY|LM|CU|U|CC|CR))(\\|_[^\n]+?\\)|^(BCD[-\n]+|",
            r"COMPONENTS|DRIVERS|ELAM|HARDWARE|SAM|Schema|SECURITY|SOFTWARE|SYSTEM|AppEvents|Console|Control Panel|Environment|EUDC|Keyboard Layout|Network|Printers|Uninstall|Volatile Environment)",
            r"\\|(^\\?|\\)S\-\d+[^\n]*?\\|",
            r"\[(Install Path|[Music Path]|Pictures Path|Videos Path|Artist|App Data Path|Name)\]|",
            "\"AppliesTo\"|\"AssociateFiles\"|",
            r"\[App Data Path\]|",
            "\"Common\"|\"CommonEmojiTerminators\"|\"Complete\"|\"",
            "(Configuration|DefaultFeature|Description|DiskPrompt|DocumentationShortcuts|EnvironmentPathNode|EnvironmentPathNpmModules|Extensions|External Program Arguments|File Location.*?|MainApplication|MainFeature|NodeRuntime|Path|Servicing_Key|Shortcuts)\"",
            r")",
            r"([^\n#]*?)\\?\S+)($|[^\\]+$)"
        ]
        .join("")
    ).unwrap();
}

pub fn is_registry_key(value: &str) -> bool {
    //! Checks to see if a Given String is a registry key
    if value.is_empty() {
        return false;
    }
    REGISTRY.is_match(value)
}
