import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset, Subset
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, precision_score, recall_score, f1_score
import os
import time
from dga_model import DGAModel, CHAR_TO_IDX, MAX_LEN, MODEL_PATH, device, VOCAB_SIZE

class DGADataset(Dataset):
    def __init__(self, csv_path):
        df = pd.read_csv(csv_path)
        # Professional cleaning
        df['domain'] = df['domain'].astype(str).str.lower()
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        self.domains = df['domain'].tolist()
        self.labels = df['label'].astype(float).tolist()
        print(f"[*] Dataset loaded: {len(self.domains)} samples")
        print(f"[*] Distribution - Benign: {self.labels.count(0)}, Malicious: {self.labels.count(1)}")

    def __len__(self):
        return len(self.domains)

    def __getitem__(self, idx):
        domain = self.domains[idx]
        label = self.labels[idx]
        
        # Sequence Padding/Truncation
        indices = [CHAR_TO_IDX.get(c, 0) for c in domain[:MAX_LEN]]
        if len(indices) < MAX_LEN:
            indices += [0] * (MAX_LEN - len(indices))
        
        return (torch.tensor(indices, dtype=torch.long), 
                torch.tensor([len(domain)], dtype=torch.float), 
                torch.tensor(label, dtype=torch.float))

def train_precise_model(csv_path, epochs=50, batch_size=32, lr=0.0005):
    dataset = DGADataset(csv_path)
    train_idx, val_idx = train_test_split(list(range(len(dataset))), test_size=0.2, random_state=42)
    
    train_loader = DataLoader(Subset(dataset, train_idx), batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(Subset(dataset, val_idx), batch_size=batch_size)
    
    model = DGAModel(vocab_size=VOCAB_SIZE).to(device)
    
    # Precise Optimizer: AdamW with Weight Decay for regularization
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    
    # Learning Rate Scheduler: Reduces LR when validation plateaues
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='max', factor=0.5, patience=5)
    
    # Focal Loss (simulated with BCE) for handling class imbalance if any
    criterion = nn.BCEWithLogitsLoss()
    
    best_f1 = 0
    patience = 15
    counter = 0
    
    print("[*] Starting Precise Training Engine...")
    print("[*] Target Architecture: LSTM-RNN with Feature Injection")
    
    for epoch in range(epochs):
        model.train()
        train_loss = 0
        start_time = time.time()
        
        for inputs, lengths, labels in train_loader:
            inputs, lengths, labels = inputs.to(device), lengths.to(device), labels.to(device).unsqueeze(1)
            optimizer.zero_grad()
            outputs = model(inputs, lengths)
            loss = criterion(outputs, labels)
            loss.backward()
            
            # Gradient Clipping to prevent exploding gradients
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            
            optimizer.step()
            train_loss += loss.item()
            
        # Comprehensive Validation
        model.eval()
        val_preds = []
        val_labels = []
        with torch.no_grad():
            for inputs, lengths, labels in val_loader:
                inputs, lengths = inputs.to(device), lengths.to(device)
                outputs = model(inputs, lengths)
                probs = torch.sigmoid(outputs)
                val_preds.extend(probs.cpu().numpy().flatten())
                val_labels.extend(labels.numpy().flatten())
        
        # Binary classifications for precision/recall
        y_true = np.array(val_labels)
        y_pred = (np.array(val_preds) > 0.5).astype(int)
        
        auc = roc_auc_score(y_true, val_preds)
        f1 = f1_score(y_true, y_pred)
        precision = precision_score(y_true, y_pred)
        recall = recall_score(y_true, y_pred)
        
        elapsed = time.time() - start_time
        print(f"Epoch {epoch+1:02d} | Loss: {train_loss/len(train_loader):.4f} | AUC: {auc:.4f} | F1: {f1:.4f} | Prec: {precision:.4f} | Rec: {recall:.4f} | {elapsed:.1f}s")
        
        scheduler.step(auc)
        
        if f1 > best_f1:
            best_f1 = f1
            # dga_model.get_model() loads exactly this path at inference time.
            torch.save(model.state_dict(), MODEL_PATH)
            print(f"  [+] Performance Checkpoint: New Best F1 Score: {f1:.4f}")
            counter = 0
        else:
            counter += 1
            if counter >= patience:
                print("[*] Convergence reached. Early stopping triggered.")
                break

    print("\n" + "="*50)
    print("PRECISE TRAINING SUMMARY")
    print("="*50)
    print(f"Best Validation F1: {best_f1:.4f}")
    print(f"Model Artifact: {MODEL_PATH}")
    print("="*50)

if __name__ == "__main__":
    import sys
    torch.manual_seed(42)
    np.random.seed(42)
    if len(sys.argv) > 1:
        train_precise_model(sys.argv[1])
    else:
        # Default: the committed DGA dataset next to this file.
        train_precise_model(os.path.join(os.path.dirname(os.path.abspath(__file__)), "dga_dataset.csv"))
