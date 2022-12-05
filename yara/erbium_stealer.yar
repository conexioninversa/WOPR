rule win_erbium_stealer_a1 {

    meta:
        author       = "Johannes Bader @viql"
        version      = "v1.0"
        tlp          = "TLP:WHITE"
        date         = "2022-09-01"
        description  = "detects the unpacked Erbium stealer"
        hash1_md5    = "e719388778f14e77819a62c5759d114b"
        hash1_sha1   = "540fe15ae176cadcfa059354fcdfe59a41089450"
        hash1_sha256 = "d932a62ab0fb28e439a5a7aab8db97b286533eafccf039dd079537ac9e91f551"
        hash2_md5    = "74f53a6ad69f61379b6ca74144b597e6"
        hash2_sha1   = "f188b5edc93ca1e250aee92db84f416b1642ec7f"
        hash2_sha256 = "d45c7e27054ba5d38a10e7e9d302e1d6ce74f17cf23085b65ccfba08e21a8d0b"

    strings:
        $str_path            = "ErbiumDed/api.php?method=getstub&bid=" wide
        $str_tag             = "malik_here" ascii
        $fowler_noll_vo_hash = {C5 9D 1C 81 [1-100] 93 01 00 01}
        //$zw = {00 DE 10 F3 DA}

    condition:
        uint16(0) == 0x5A4D and 
        (
            all of ($str_*) and #fowler_noll_vo_hash >= 2 
        )
}