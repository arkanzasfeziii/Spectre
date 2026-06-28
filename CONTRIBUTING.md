# Contributing to Spectre

## Setup

```bash
git clone https://github.com/arkanzasfeziii/Spectre.git
cd Spectre
pip install -r requirements.txt
pip install ruff pytest
make test
```

## Adding a New Module

1. Create `spectre/modules/your_module.py` extending `BaseModule`
2. Implement `run(ctx) -> List[AttackResult]`
3. Register in `spectre/cli.py: MODULE_REGISTRY`
4. Update `spectre/modules/__init__.py`
