"""Import a package tree and print the shared objects this process maps."""
import importlib, pkgutil, sys, warnings
warnings.filterwarnings("ignore")
for root in sys.argv[1:]:
    mod = importlib.import_module(root)
    for info in pkgutil.walk_packages(getattr(mod, "__path__", []), root + "."):
        try:
            importlib.import_module(info.name)
        except BaseException:
            pass
seen = set()
for line in open("/proc/self/maps"):
    parts = line.split()
    if len(parts) >= 6 and ".so" in parts[5]:
        seen.add(parts[5])
print("\n".join(sorted(seen)))
