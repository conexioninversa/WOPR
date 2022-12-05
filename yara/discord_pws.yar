rule win_discordpws_j1 {

    meta:
        author      = "Johannes Bader @viql"
        version     = "v1.0"
        tlp         = "TLP:WHITE"
        date        = "2021-10-01"
        description = "detects a Discord password stealer"

    strings:
        $str_services_1 = "Roaming\\Discord" wide
        $str_services_2 = "Roaming\\discordcanary" wide
        $str_services_3 = "Roaming\\discordptb" wide
        $str_services_4 = "Local\\Google\\Chrome\\User Data\\Default" wide
        $str_services_5 = "Local\\Naver\\Naver Whale\\User Data\\Default" wide
        $str_services_6 = "Roaming\\Opera Software\\Opera Stable" wide
        $str_services_7 = "Local\\BraveSoftware\\Brave-Browser\\User Data\\Default" wide
        $str_services_8 = "Local\\Yandex\\YandexBrowser\\User Data\\Default" wide

        $str_token_1 = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}" wide
        $str_token_2 = "mfa\\.[\\w-]{84}" wide

    condition:
        uint16(0) == 0x5A4D and 
        all of ($str_services_*) and 
        all of ($str_token_*)
}