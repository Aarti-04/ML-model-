import tensorflow as tf
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences

# Sample text data
texts = [
    "This is a sample sentence.",
    "Another example sentence.",
    "Yet another example for demonstration."
]

# Define tokenizer
tokenizer = Tokenizer()
tokenizer.fit_on_texts(texts)

# Tokenize texts
sequences = tokenizer.texts_to_sequences(texts)

# Pad sequences to a maximum length
max_length = max(len(seq) for seq in sequences)
padded_sequences = pad_sequences(sequences, maxlen=max_length, padding='post')

# Print tokenized and padded sequences
print("Tokenized sequences:")
print(sequences)
print("\nPadded sequences:")
print(padded_sequences)