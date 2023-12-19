
class Target:

    tlsv1_2: bool = None
    tlsv1: bool = None

    def __init__(self, remote: str, port: int, use_ldaps: bool) -> None:
        self.remote = remote
        self.port = port
        self.use_ldaps = use_ldaps

    def use_tls(self) -> bool:
        return self.use_ldaps if self.use_ldaps else self.tlsv1_2 or self.tlsv1
