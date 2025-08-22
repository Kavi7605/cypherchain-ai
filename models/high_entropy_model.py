# Create high_entropy_model.py
import os
import random

# Generate high-entropy data (simulates encrypted payload)
high_entropy_data = os.urandom(10000)  # Random bytes = high entropy

with open("high_entropy_model.pth", "wb") as f:
    f.write(high_entropy_data)

print("Created high-entropy test file")
