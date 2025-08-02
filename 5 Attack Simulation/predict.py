import sys
import joblib
import json
from os import mkfifo, path
import numpy as np

# Custom JSON encoder to handle numpy types
class NumpyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return super(NumpyEncoder, self).default(obj)

# Load model
model = joblib.load('models/xgboost.pkl')

# Feature order from Zeek's CSV output
FEATURE_ORDER = [
    'id_resp_p', 'proto', 'service', 'duration', 
    'orig_bytes', 'resp_bytes', 'conn_state', 'missed_bytes',
    'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes'
]

def parse_csv_line(line):
    """Parse CSV line into feature dictionary with proper types"""
    values = line.strip().split(',')
    if len(values) != len(FEATURE_ORDER):
        raise ValueError(f"Expected {len(FEATURE_ORDER)} features, got {len(values)}")
    
    # Convert to appropriate types
    return {
        'id_resp_p': int(values[0]),
        'proto': int(values[1]),
        'service': int(values[2]),
        'duration': float(values[3]),
        'orig_bytes': float(values[4]),
        'resp_bytes': float(values[5]),
        'conn_state': int(values[6]),
        'missed_bytes': int(values[7]),
        'orig_pkts': int(values[8]),
        'orig_ip_bytes': int(values[9]),
        'resp_pkts': int(values[10]),
        'resp_ip_bytes': int(values[11])
    }

def predict(features):
    """Make prediction using the model"""
    input_data = [[
        features['id_resp_p'],
        features['proto'],
        features['service'],
        features['duration'],
        features['orig_bytes'],
        features['resp_bytes'],
        features['conn_state'],
        features['missed_bytes'],
        features['orig_pkts'],
        features['orig_ip_bytes'],
        features['resp_pkts'],
        features['resp_ip_bytes']
    ]]
    
    proba = model.predict_proba(input_data)[0][1]
    # Convert numpy float32 to native Python float
    return 1 if proba > 0.5 else 0, float(proba)

# ... (keep the top of your script the same)

if __name__ == "__main__":
    PIPE_PATH = '/tmp/zeek_pipe'
    if not path.exists(PIPE_PATH):
        mkfifo(PIPE_PATH, 0o666)
    
    print("Waiting for Zeek JSON data...", file=sys.stderr)
    with open(PIPE_PATH, 'r') as pipe:
        while True:
            line = pipe.readline().strip()
            if line:
                try:
                    # Parse the entire line as a JSON object
                    features = json.loads(line)
                    
                    # Make prediction
                    prediction, confidence = predict(features)
                    
                    # Create result with original features
                    result = {
                        "prediction": prediction,
                        "confidence": confidence,
                        "features": features
                    }
                    
                    # Output result as JSON with custom encoder
                    print(json.dumps(result, cls=NumpyEncoder))
                    sys.stdout.flush()

                # ADD THIS BLOCK TO CATCH ONLY JSON ERRORS AND CONTINUE
                except json.JSONDecodeError:
                    # This happens when tail reads an incomplete line. It's safe to ignore.
                    # print(f"Skipping incomplete JSON line: {line}", file=sys.stderr)
                    continue 
                except Exception as e:
                    print(f"An unexpected error occurred: {str(e)}", file=sys.stderr)
