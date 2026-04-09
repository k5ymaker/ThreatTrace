/*
 * ThreatTrace YARA Rules - Cross-Site Scripting (XSS) Detection
 * Category: Apache / Web Application
 * Author: ThreatTrace
 */

rule ThreatTrace_XSS_ScriptTag {
    meta:
        description = "XSS - Raw and URL-encoded <script> tag injection"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1059.007"
    strings:
        $s1 = "<script" nocase
        $s2 = "%3Cscript" nocase
        $s3 = "%3cscript" nocase
        $s4 = "&#x3C;script" nocase
        $s5 = "&#60;script" nocase
        $s6 = "&lt;script" nocase
        $s7 = "<SCRIPT" ascii
    condition:
        any of them
}

rule ThreatTrace_XSS_JavascriptProtocol {
    meta:
        description = "XSS - javascript: protocol injection in href or src attributes"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1059.007"
    strings:
        $js1 = "javascript:" nocase
        $js2 = "javascript%3A" nocase
        $js3 = "javascript%3a" nocase
        $js4 = "JAVASCRIPT:" ascii
        $js5 = "j&#97;vascript:" nocase
        $js6 = "j&#x61;vascript:" nocase
        $vbs = "vbscript:" nocase
    condition:
        any of them
}

rule ThreatTrace_XSS_DOMEventHandlers {
    meta:
        description = "XSS - DOM event handler injection (onerror, onload, onmouseover)"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1059.007"
    strings:
        $ev1 = "onerror=" nocase
        $ev2 = "onload=" nocase
        $ev3 = "onmouseover=" nocase
        $ev4 = "onclick=" nocase
        $ev5 = "onmouseout=" nocase
        $ev6 = "onfocus=" nocase
        $ev7 = "onblur=" nocase
        $ev8 = "onkeypress=" nocase
        $ev9 = "onsubmit=" nocase
        $ev10 = "ondblclick=" nocase
        $ev11 = "onpointerover=" nocase
        $ev12 = "onanimationstart=" nocase
    condition:
        any of them
}

rule ThreatTrace_XSS_DialogFunctions {
    meta:
        description = "XSS - JavaScript dialog functions alert, confirm, prompt used as payloads"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1059.007"
    strings:
        $d1 = "alert(" nocase
        $d2 = "alert%28" nocase
        $d3 = "confirm(" nocase
        $d4 = "prompt(" nocase
        $d5 = "alert`" nocase
        $d6 = "window.alert(" nocase
    condition:
        any of them
}

rule ThreatTrace_XSS_DocumentCookieStealing {
    meta:
        description = "XSS - document.cookie access indicating cookie theft attempt"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1539"
    strings:
        $c1 = "document.cookie" nocase
        $c2 = "document%2ecookie" nocase
        $c3 = "document[\"cookie\"]" nocase
        $c4 = "document['cookie']" nocase
        $c5 = "document.cookie+" nocase
    condition:
        any of them
}

rule ThreatTrace_XSS_EvalExecution {
    meta:
        description = "XSS - eval() function injection for arbitrary JavaScript execution"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1059.007"
    strings:
        $e1 = "eval(" nocase
        $e2 = "eval%28" nocase
        $e3 = "eval(atob(" nocase
        $e4 = "eval(unescape(" nocase
        $e5 = "eval(String.fromCharCode(" nocase
        $e6 = "Function(" nocase
        $e7 = "setTimeout(" nocase
        $e8 = "setInterval(" nocase
    condition:
        any of them
}

rule ThreatTrace_XSS_Base64EncodedScript {
    meta:
        description = "XSS - Base64-encoded script content decoded and injected"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1059.007"
    strings:
        $b1 = "atob(" nocase
        $b2 = "fromBase64" nocase
        $b3 = "base64," nocase
        $b4 = "PHNjcmlwdA" // base64 of <script
        $b5 = "PHNjcmlwdD" // base64 variant
        $b6 = "data:text/html;base64," nocase
        $b7 = "data:application/javascript;base64," nocase
    condition:
        any of them
}

rule ThreatTrace_XSS_SVGBasedInjection {
    meta:
        description = "XSS - SVG tag used as XSS vector with onload event"
        author = "ThreatTrace"
        severity = "HIGH"
        mitre_technique = "T1059.007"
    strings:
        $svg1 = "<svg onload=" nocase
        $svg2 = "<svg/onload=" nocase
        $svg3 = "%3Csvg+onload=" nocase
        $svg4 = "<svg%20onload=" nocase
        $svg5 = "<svg><script>" nocase
        $svg6 = "<svg xmlns=" nocase
        $svg7 = "<animate onbegin=" nocase
        $svg8 = "<set onbegin=" nocase
    condition:
        any of them
}

rule ThreatTrace_XSS_ImgTagInjection {
    meta:
        description = "XSS - IMG tag used as XSS vector via src or event handlers"
        author = "ThreatTrace"
        severity = "MEDIUM"
        mitre_technique = "T1059.007"
    strings:
        $img1 = "<img src=x onerror=" nocase
        $img2 = "<img/src=x onerror=" nocase
        $img3 = "<img src=\"x\" onerror=" nocase
        $img4 = "<img%20src=x%20onerror=" nocase
        $img5 = "<IMG SRC=javascript:" nocase
        $img6 = "<img src=1 onerror=" nocase
        $img7 = "%3Cimg+src%3Dx+onerror" nocase
    condition:
        any of them
}
