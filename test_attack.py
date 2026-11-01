import pandas as pd

# NSL-KDD dataset load करें
df = pd.read_csv(
    "datasets/KDDTrain+.txt",
    header=None
)

# Dataset में attack type खोजें
attack_data = df[df[41] == "neptune"]

# पहला attack sample निकालें
sample = attack_data.iloc[0]

# Features निकालें (पहले 41 columns)
features = sample.iloc[:41]

# Feature names
feature_names = [
    "duration", "protocol_type", "service", "flag",
    "src_bytes", "dst_bytes", "land", "wrong_fragment",
    "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count",
    "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate"
]

# JSON format में print करें
result = {
    name: value.item() if hasattr(value, "item") else value
    for name, value in zip(feature_names, features.tolist())
}

import json
print(json.dumps({"features": result}, indent=2))