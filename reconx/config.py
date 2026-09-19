from dataclasses import dataclass, field
from pathlib import Path
import yaml

DEFAULT_CONFIG_PATH = Path("config.yaml")


@dataclass
class GeneralConfig:
    project_name: str = "reconx"
    output_dir: str = "results"
    log_level: str = "INFO"
    log_file: str = "reconx.log"


@dataclass
class NetworkConfig:
    timeout: int = 10
    retries: int = 2
    delay_min: float = 0.5
    delay_max: float = 1.5
    rate_limit: int = 10
    concurrency: int = 5
    proxies: list = field(default_factory=list)
    proxy_rotate: bool = False
    user_agents: list = field(default_factory=list)


@dataclass
class ModulesConfig:
    subdomain: bool = True
    dns: bool = True
    portscan: bool = True
    httpprobe: bool = True


@dataclass
class PortScanConfig:
    ports: str = "1-1024"
    scan_type: str = "connect"
    randomize: bool = True


@dataclass
class HttpConfig:
    follow_redirects: bool = True
    verify_tls: bool = False
    max_body_size: int = 65536


@dataclass
class AppConfig:
    general: GeneralConfig = field(default_factory=GeneralConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    modules: ModulesConfig = field(default_factory=ModulesConfig)
    portscan: PortScanConfig = field(default_factory=PortScanConfig)
    http: HttpConfig = field(default_factory=HttpConfig)


def _build(cls, data: dict):
    valid = {f.name for f in cls.__dataclass_fields__.values()}
    return cls(**{k: v for k, v in (data or {}).items() if k in valid})


def load_config(path: str | Path = DEFAULT_CONFIG_PATH) -> AppConfig:
    path = Path(path)
    if not path.exists():
        return AppConfig()
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return AppConfig(
        general=_build(GeneralConfig, raw.get("general")),
        network=_build(NetworkConfig, raw.get("network")),
        modules=_build(ModulesConfig, raw.get("modules")),
        portscan=_build(PortScanConfig, raw.get("portscan")),
        http=_build(HttpConfig, raw.get("http")),
    )
