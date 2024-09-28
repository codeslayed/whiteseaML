import tensorflow as tf
from tensorflow.keras import layers, models
from tensorflow.keras.datasets import mnist
from tensorflow.keras.utils import to_categorical

#Load the MNIST dataset
import numpy as np

# Load the MNIST dataset
(trainX, trainY), (testX, testY) = mnist.load_data()

# Normalize pixel values to be between 0 and 1
trainX = trainX.astype('float32') / 255.0
testX = testX.astype('float32') / 255.0

# Reshape dataset to have a single channel
trainX = trainX.reshape((trainX.shape[0], 28, 28, 1))
testX = testX.reshape((testX.shape[0], 28, 28, 1))

# One-hot encode target values
trainY = to_categorical(trainY, num_classes=10)
testY = to_categorical(testY, num_classes=10)

# Define all_data
all_data = np.concatenate((trainX, testX))

def create_dataset(data, batch_size, shuffle):
    dataset = tf.data.Dataset.from_tensor_slices(data)
    if shuffle:
        dataset = dataset.shuffle(buffer_size=len(data))
    dataset = dataset.batch(batch_size)
    return dataset

#Build a simple neural network model
model = models.Sequential([
    layers.Flatten(input_shape=(28, 28)),           # Flatten the input
    layers.Dense(128, activation='relu'),           # Hidden layer with ReLU activation
    layers.Dropout(0.2),                            # Dropout layer for regularization
    layers.Dense(10, activation='softmax')          # Output layer with softmax activation
])

#Compile the model
model.compile(optimizer='adam',
             loss='categorical_crossentropy',
              metrics=['accuracy'])

# Split the data into training and validation sets

train_size = int(0.9 * len(trainX))
train_images = trainX[:train_size]
train_labels = trainY[:train_size]
validation_images = trainX[train_size:]
validation_labels = trainY[train_size:]

# Create datasets for training and validation
train_dataset = tf.data.Dataset.from_tensor_slices((train_images, train_labels))
train_dataset = train_dataset.batch(10)
train_dataset = train_dataset.shuffle(buffer_size=len(train_images))

validation_dataset = tf.data.Dataset.from_tensor_slices((validation_images, validation_labels))
validation_dataset = validation_dataset.batch(10)
#Train the model
model.fit(train_dataset, epochs=70, validation_data=validation_dataset)

#Evaluate the model on test data
test_loss, test_acc = model.evaluate(testX, testY)
print(f'Test accuracy: {test_acc}')

#Save the model in .h5 format
model.save('model1.h5')
print("Model saved as 'model1.h5'")
