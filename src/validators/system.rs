use fancy_regex::Regex;

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
    static ref SQL: Regex = Regex::new(
        &[
            r"(?xmi)(",
            r"^[^\S\n]*",
            r"(",
            r"INSERT\b((?!^[^\S\n]*$)[\s\S])+?\bVALUES\b.*",
            r"|FROM\b((?!^[^\S\n]*$)[\s\S])+?\bWHERE\b.*",
            r"|(SELECT|PATINDEX)\b((?!^[^\S\n]*$)[\s\S])+?\b(WHERE|FROM|AS)\b.*",
            r"|BEGIN\b((?!^[^\S\n]*$)[\s\S])+?\bEND\b.*",
            r"|(SELECT|UPDATE|DELETE|INSERT[ ]INTO|CREATE[ ]DATABASE|ALTER[ ]DATABASE|CREATE[ ]TABLE|ALTER[ ]TABLE|DROP[ ]TABLE|CREATE[ ]INDEX|DROP[ ]INDEX|DECLARE|SET|TRUNCATE|ADD|WHERE)\b",
            r".*",
            r")",
            r"(\(?((?!^[^\S\n]*$)[\s\S])+?\)[^)\n]*)?",
            r"(\n|$)",
            r")+"
        ]
        .join("")
    ).unwrap();
}

pub fn is_registry_key(value: &str) -> bool {
    //! Checks to see if a Given String is a registry key
    if value.is_empty() {
        return false;
    }
    REGISTRY.is_match(value).unwrap_or_default()
}

pub fn is_sql(value: &str) -> bool {
    //! Checks to see if a Given String is a SQL statement
    if value.is_empty() {
        return false;
    }

    SQL.is_match(value).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_registry_key() {
        // invalid
        assert!(is_registry_key("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"));
        assert!(is_registry_key("SOFTWARE\\Microsoft\\Windows\\CurrentVersion"));
        assert!(is_registry_key("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"));
        assert!(is_registry_key("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"));

        // invalid
        assert!(!is_registry_key("This\nIs\\aRegistryKey"));
    }

    #[test]
    fn test_is_sql() {
        // invalid
        assert!(is_sql("SELECT * FROM xyz"));
        assert!(is_sql("SELECT * FROM xyz WHERE x LIKE '%y%';"));
        assert!(is_sql("INSERT INTO Country(CountryID,CountryName) VALUES (1,'United States')"));
        assert!(is_sql(r#"CREATE TABLE table_name (
        column1 INTEGER,
        column2 VARCHAR2,
        column3 INTEGE);"#));

        // invalid
        assert!(!is_registry_key("Select this is NOT a SQL Query WHERE it could get selected="));
    }
}