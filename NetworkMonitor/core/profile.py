from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class Profile:
    name: str
    data: Dict[str, Any] = field(default_factory=dict)
