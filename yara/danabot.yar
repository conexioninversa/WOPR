rule win_danabot {

    meta:
        author      = "Johannes Bader @viql"
        date        = "2022-04-19"
        version     = "v1.1"
        description = "detects DanaBot"
        hash1       = "b7f891f4ed079420e16c4509680cfad824b061feb94a0d801c96b82e1f7d52ad"
        hash1b      = "62174157b42e5c8c86b05baf56dfd24b"
        hash2       = "c8f27c0e0d4e91b1a6f62f165d45d8616fc24d9c798eb8ab4269a60e29a2de5e"
        hash3       = "5cb70c87f0b98279420dde0592770394bf8d5b57df50bce4106d868154fd74cb"
        tlp         = "TLP:WHITE"
        malpedia_family = "win.danabot"

    strings:
        $keyboard = { C6 05 [4] 71 C6 05 [4] 77 C6 05 [4] 65 C6 05 [4] 72 C6 05 [4] 74 C6 05 [4] 79 C6 05 [4] 75 C6 05 [4] 69 C6 05 [4] 6F  }
        $move_y   = { 8B 45 F8 C6 80 [4] 79 } // mov     eax, [ebp-8], mov     byte ptr <addr>[eax], 79h
        $id_str   = /[A-F0-9]{32}zz/

    condition:
        uint16(0) == 0x5A4D and 
        (
            all of them 
        )
}