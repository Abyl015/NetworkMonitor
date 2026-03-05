from dataclasses import dataclass

@dataclass
class Profile:
    name: str
    train_packets: int = 500
    sample_factor: int = 20
    scan_ports_threshold: int = 50
    dos_pps_eff_threshold: int = 100
    retrain_every_sec: int = 180
    buffer_size: int = 3000
    contamination: float = 0.005
    n_estimators: int = 50

DEMO = Profile(
    name="DEMO",
    train_packets=300,
    sample_factor=10,
    scan_ports_threshold=30,
    dos_pps_eff_threshold=80,
    retrain_every_sec=120,
    buffer_size=2000,
    contamination=0.01,
    n_estimators=50,
)

NORMAL = Profile(
    name="NORMAL",
    train_packets=500,
    sample_factor=20,
    scan_ports_threshold=50,
    dos_pps_eff_threshold=100,
    retrain_every_sec=180,
    buffer_size=3000,
    contamination=0.005,
    n_estimators=50,
)
