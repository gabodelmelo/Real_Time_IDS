import scapy.all as scapy
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib  
import queue
import time

# Initialize packet queue
packet_queue = queue.Queue()

# Define the columns based on trained model
required_columns = [
    'protocol_type', 'service', 'flag', 'duration', 'src_bytes', 'dst_bytes',
    'count', 'srv_count', 'serror_rate', 'rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'dst_host_count', 'dst_host_srv_count', 'num_root',
    'num_file_creations', 'num_access_files', 'num_shells', 'num_outbound_cmds',
    'num_failed_logins', 'logged_in', 'is_guest_login', 'is_host_login',
    'root_shell', 'urgent', 'hot', 'land', 'wrong_fragment', 'srv_rerror_rate',
    'srv_serror_rate', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'su_attempted', 'num_compromised'
]

# Function to train the model
def train_model(features, labels):
    # preprocessing steps
    numeric_features = required_columns

    # Column Transformer
    preprocessor = ColumnTransformer(
        transformers=[
            ('num', StandardScaler(), numeric_features)
        ]
    )

    # Pipeline with preprocessing and model
    model_pipeline = Pipeline(steps=[
        ('preprocessor', preprocessor),
        ('classifier', RandomForestClassifier())
    ])

    # Train the model
    model_pipeline.fit(features[numeric_features], labels)
    return model_pipeline

def load_or_train_model():
    model_pipeline = joblib.load('model.pkl')  # Load the model
    return model_pipeline

def capture_packets(interface):
    """Capture network packets and enqueue them for processing."""
    def packet_callback(packet):
        print(f"Packet captured: {packet.summary()}")  # Print summary of the captured packet
        # Process only IP packets
        if packet.haslayer(scapy.IP):
            packet_data = {
                'protocol_type': packet[scapy.IP].proto,
                'service': 'tcp' if packet.haslayer(scapy.TCP) else 'udp',
                'flag': packet[scapy.IP].flags,
                'duration': packet.time,  
                'src_bytes': len(packet[scapy.IP].payload),
                'dst_bytes': 0,  
                'count': 1, 
                'srv_count': 0,
                'serror_rate': 0,
                'rerror_rate': 0, 
                'same_srv_rate': 0, 
                'diff_srv_rate': 0,
                'dst_host_count': 0,
                'dst_host_srv_count': 0, 
                'num_root': 0,
                'num_file_creations': 0,
                'num_access_files': 0,
                'num_shells': 0,
                'num_outbound_cmds': 0,
                'num_failed_logins': 0,
                'logged_in': 0,
                'is_guest_login': 0,
                'is_host_login': 0,
                'root_shell': 0,
                'urgent': 0,
                'hot': 0,
                'land': 0,
                'wrong_fragment': 0,
                'srv_rerror_rate': 0,
                'srv_serror_rate': 0,
                'dst_host_same_srv_rate': 0,
                'dst_host_diff_srv_rate': 0,
                'dst_host_same_src_port_rate': 0,
                'dst_host_srv_diff_host_rate': 0,
                'su_attempted': 0,
                'num_compromised': 0 
            }
            packet_queue.put(pd.DataFrame([packet_data]))  # Convert dict to DataFrame
        else:
            print("Non-IP packet captured.")

    scapy.sniff(iface=interface, prn=packet_callback, filter="tcp or udp", store=0)

def process_incoming_packets(model_pipeline):
    while True:
        if not packet_queue.empty():
            incoming_data = packet_queue.get()
            print("Incoming Data:", incoming_data)

            # Create a DataFrame with the required columns
            for column in required_columns:
                if column not in incoming_data.columns:
                    incoming_data[column] = 0  # Add missing columns with a default value

            incoming_data = incoming_data[required_columns]  # Reorder columns to match the model's 

            # Make the prediction
            try:
                prediction = model_pipeline.predict(incoming_data)
                print("Prediction:", prediction)
            except Exception as e:
                print("Prediction error:", e)

def main():
    interface = "enp0s3"  # network interface
    model_pipeline = load_or_train_model()
    print("Model loaded.")

    # Start capturing packets
    capture_packets(interface)

    # Start processing incoming packets
    process_incoming_packets(model_pipeline)

if __name__ == "__main__":
    main()
