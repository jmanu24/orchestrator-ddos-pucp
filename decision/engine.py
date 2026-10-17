import config.settings as settings


class Decision:

    def __init__(self, detector, src_ip, score, attack_type):
        self.detector = detector
        self.src_ip = src_ip
        self.score = score
        self.attack_type = attack_type


class DecisionEngine:

    def __init__(self):

        # `score` here is a ratio (observed pps / that protocol's threshold,
        # e.g. 24.4 for an ICMP flood at 24.4x ICMP_THRESHOLD) — not an
        # absolute pps count. DECISION_THRESHOLD (config/settings.py) is
        # calibrated against that ratio: 1.5 means "confirmed past its own
        # threshold, weighted", not "200x any protocol's threshold", which
        # is what the previous hardcoded value of 200 effectively required
        # — only an extreme flood (hundreds of thousands of pps) could ever
        # cross it, so moderate attacks got detected but never mitigated.
        self.global_threshold = settings.DECISION_THRESHOLD

        # ponderación por tipo de ataque
        self.weights = {
            "SYN_FLOOD": 1.0,
            "UDP_FLOOD": 0.9,
            "ICMP_FLOOD": 0.8,
            "DDOS_DISTRIBUTED": 1.3,
            # A distributed flood whose sources span multiple domains at
            # once needs coordinated mitigation across separate control
            # planes (OpenFlow drop rule, mobile RC-queue UE kill, BNG
            # session-stop+DHCP blacklist) simultaneously -- strictly
            # more severe to fully mitigate than a single-domain
            # DDOS_DISTRIBUTED, one tier up continuing the ~0.1 spacing
            # above. Independent of (not double-counting) DDoSDetectionEngine.
            # MULTIDOMAIN_BOOST, which is a confidence multiplier at the
            # detection layer, not a score weight here.
            "MULTIDOMAIN_DISTRIBUTED_ATTACK": 1.4,
        }

    def evaluate(self, detections):

        if not detections:
            return None

        scored = []

        for d in detections:

            attack_type = d.get("type")
            src_ip = d.get("src_ip")
            score = d.get("score", 0)

            weight = self.weights.get(attack_type, 1.0)

            final_score = score * weight

            scored.append({
                "type": attack_type,
                "src_ip": src_ip,
                "score": final_score,
                "detector": attack_type
            })

        # seleccionar el ataque más fuerte
        best = max(scored, key=lambda x: x["score"])

        # decisión final
        if best["score"] < self.global_threshold:
            return None

        return Decision(
            detector=best["detector"],
            src_ip=best["src_ip"],
            score=best["score"],
            attack_type=best["type"]
        )
