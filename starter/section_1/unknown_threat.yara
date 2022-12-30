rule malicious_script {
        meta:
                Author = "@Roaa"
                Description = "the rule detects the presence of malicious scripts associated to the darkl0rd domain activity"
        strings:
                $domain = "darkl0rd.com"
        condition:
                $domain
}
