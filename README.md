# Real-Time Intrusion Detection System (IDS)

## Overview

This project implements a real-time Intrusion Detection System (IDS) using network packet analysis and machine learning. The IDS captures network packets from a specified interface, extracts relevant features, and uses a pre-trained machine learning model to classify network traffic as benign or malicious. The primary objective of this project is to monitor network activity and detect potential intrusions in real-time, providing essential information for cybersecurity and network monitoring purposes.

The project leverages the scapy library for packet capture and feature extraction, and a RandomForestClassifier from the sklearn library for predictive modeling. This IDS can be deployed in environments where network security is a priority, offering an automated and proactive solution to identify threats in real time.

## Key Objectives

- Real-Time Packet Capture: Continuously capture network packets and extract relevant features from each packet.
- Data Transformation for Prediction: Ensure each captured packet’s data aligns with the features required by the pre-trained machine learning model.
- Intrusion Detection: Use a machine learning model to classify network packets in real-time, providing predictions on potential intrusions.
- Scalability: Enable multi-threaded packet capture and processing to handle high network traffic without packet loss.

Steps Taken
1. Project Setup

    Installed necessary libraries including scapy for packet capture, pandas for data handling, and scikit-learn for machine learning model training and prediction.
    Defined the key features (required_columns) for packet data to ensure consistency with the trained model.

2. Model Preparation

    Created a function, train_model, that standardizes the selected features and trains a RandomForestClassifier. This function is used to train the model initially if needed.
    Added functionality to load the pre-trained model (load_or_train_model) from a saved file (model.pkl) for real-time use. This reduces training time and ensures quick deployment.
    Established a feature pipeline with data preprocessing (standardization via StandardScaler) and model prediction in sklearn's Pipeline.

3. Real-Time Packet Capture and Processing

    Configured capture_packets to monitor a specified network interface, filter TCP and UDP traffic, and extract relevant features from each IP packet.
    Implemented placeholders for some features and a basic structure to expand calculations in future work (e.g., duration, srv_count, serror_rate).
    Used a queue to store captured packets for processing, ensuring that packet capture and model prediction could operate independently for better performance.

4. Prediction Processing

    Created process_incoming_packets to dequeue packets, fill any missing features with default values, and reorder columns to align with the model’s expected input format.
    Implemented the machine learning model’s predict function to classify each packet in real time. Added exception handling to manage errors during prediction.

5. Multi-Threading and Deployment

    Integrated multi-threading to handle both packet capture and processing simultaneously. This improves throughput and ensures efficient real-time detection.
    Configured the main function to initialize the network interface, load the model, and start threads for packet capture and packet processing.

## Outcome

The final project achieved a functional real-time IDS capable of capturing and classifying network packets using machine learning. The IDS successfully loads a pre-trained model and predicts intrusions based on real-time network traffic data. With multi-threading, the system is able to handle moderate traffic without packet loss. The project met its key objectives, providing a framework for an extensible and deployable IDS solution. Further improvements, such as calculating dynamic feature values and enhancing the model with additional data, could increase the IDS’s accuracy and applicability in more complex network environments.
