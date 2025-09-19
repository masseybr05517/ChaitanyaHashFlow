"""
modify_pcap_ip.py

Description:
    A Python script that modifies the IP addresses in PCAP files using tcprewrite,
    which is part of the tcpreplay suite. Make sure tcprewrite is installed.
    
    To install tcpreplay on macOS, run:
        brew install tcpreplay

    You can verify the installation with:
        which tcprewrite

    Example tcprewrite command:
        tcprewrite --pnat=152.23.0.0/16:152.23.0.1/0 --outfile=mypackets-clean.pcap --infile=messenger53_truncated.pcap

Usage:
    python3 modify_pcap_ip.py <pcap_directory> <output_pcap_directory>

This script processes all PCAP files in the specified input directory,
modifies their IP addresses according to the provided parameters, and writes
the modified PCAP files to the output directory.
"""
import argparse
import json
import signal
import sys
import zmq
import os
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from keras.callbacks import TensorBoard, ModelCheckpoint
from keras.models import Sequential
from keras.layers import Conv1D, MaxPooling1D, Flatten, Dense, Dropout, LSTM, BatchNormalization
from keras import backend as K
from keras.utils import to_categorical
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from keras.metrics import top_k_categorical_accuracy
from tensorflow.keras.callbacks import EarlyStopping
import tensorflow.keras.backend as K
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix
from sklearn.metrics import f1_score as f1_score_sklearn


def load_model(model_name , num_classes=10):
    checkpoint_dir = os.path.abspath('')
    # Create a scikit-learn pipeline
    pipeline = Pipeline([
        ('model', Sequential([
            LSTM(units=128, input_shape=(40, 2), return_sequences=True, recurrent_dropout=0.1),
            LSTM(units=64, dropout=0.1),
            Dense(64, activation='relu'),
            Dense(num_classes, activation='softmax')
        ]))
    ])
    # Compile the model with custom metrics
    pipeline.named_steps['model'].compile(loss='categorical_crossentropy', optimizer='adam',
                                          metrics=['accuracy', f1_score, precision, recall])
    # check_path = os.path.join(checkpoint_dir, model_name + '40_packets_acc.weights.h5')
    # print(os.path.abspath(check_path))
    pipeline.named_steps['model'].load_weights(model_name)
    # print("We made it past the load weights point.")
    return pipeline

def classify(X_test, pipeline):
    y_pred_prob = pipeline.predict(X_test)
    y_pred = np.argmax(y_pred_prob, axis=1)
    return y_pred

def precision(y_true, y_pred):
    true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
    predicted_positives = K.sum(K.round(K.clip(y_pred, 0, 1)))
    precision = true_positives / (predicted_positives + K.epsilon())
    return precision


def recall(y_true, y_pred):
    true_positives = K.sum(K.round(K.clip(y_true * y_pred, 0, 1)))
    possible_positives = K.sum(K.round(K.clip(y_true, 0, 1)))
    recall = true_positives / (possible_positives + K.epsilon())
    return recall


def f1_score(y_true, y_pred):
    prec = precision(y_true, y_pred)
    rec = recall(y_true, y_pred)
    return 2 * ((prec * rec) / (prec + rec))


def weighted_accuracy(y_true, y_pred, flow_sizes=40):
    total_flow_size = sum(flow_sizes)
    weighted_acc = 0
    for i, flow_size in enumerate(flow_sizes):
        if y_true[i] == y_pred[i]:
            prediction = 1
        else:
            prediction = 0
        weighted_acc += flow_size * prediction
    weighted_acc /= total_flow_size
    return weighted_acc

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Receive flow‑records over ZeroMQ and dump each JSON line."
    )
    parser.add_argument(
        "--endpoint",
        default="ipc:///tmp/flowpipe",
        help="ZMQ endpoint to connect (default: ipc:///tmp/flowpipe)",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write output to FILE instead of stdout (newline‑delimited JSON)",
    )
    args = parser.parse_args()

    # -------- ZeroMQ setup -------------------------------------------------
    ctx = zmq.Context()
    sock = ctx.socket(zmq.PULL)
    sock.connect(args.endpoint)

    # -------- output destination ------------------------------------------
    out = open(args.output, "a", encoding="utf‑8") if args.output else sys.stdout

    # -------- graceful shutdown ------------------------------------------
    def shutdown(*_):
        print("\n[worker] shutting down …", file=sys.stderr)
        sock.close(0)
        ctx.term()
        if out is not sys.stdout:
            out.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print(f"[worker] listening on {args.endpoint}", file=sys.stderr)
    model_name="checkpoint40_packets_acc.weights.h5"
    classification_model_pipeline = load_model(model_name)
    

    # -------- main receive loop ------------------------------------------
    while True:
        print("Listening\n")
        raw = sock.recv()             # blocking; bytes
        try:
            rec = json.loads(raw.decode())   # ensure the JSON is valid
            for data in rec:
                if len(data['ts']) == 40:
                    ts = data['ts']
                    length = data['len']
                    ts_len = list(zip(ts,length))
                    x_t = np.array(ts_len)
                    x_t = np.expand_dims(x_t, axis=0)
                    y_pred_prob = classification_model_pipeline.predict(x_t)
                    y_pred = np.argmax(y_pred_prob, axis=1)
                    print(f"Output: {y_pred}")
        except json.JSONDecodeError as exc:
            print(f"[worker] JSON decode error: {exc}", file=sys.stderr)
            continue

        out.write("\n")
        out.flush()


if __name__ == "__main__":
    main()
