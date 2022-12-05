rule win_neshta_1 {

    meta:
        author      = "Johannes Bader @viql"
        version     = "v1.0"
        tlp         = "TLP:WHITE"
        date        = "2021-10-01"
        description = "detects Neshta"

    strings:
        $a = "! Best regards 2 Tommy Salo. [Nov-2005] yours [Dziadulja Apanas]" ascii

    condition:
        uint16(0) == 0x5A4D and 
        $a
}