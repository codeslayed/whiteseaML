import streamlit as st
from PIL import Image

def main():
    st.title("Image Upload and Description App")

    # Image upload
    uploaded_image = st.file_uploader("Upload an Image", type=["jpg", "jpeg", "png"])

    # Text area for description
    description = st.text_area("Describe the image here:")

    # Button to send the query
    if st.button("Send Query"):
        if uploaded_image is not None and description:
            # Display the uploaded image
            image = Image.open(uploaded_image)
            st.image(image, caption='Uploaded Image', use_column_width=True)

            # Display the description
            st.write("Description:", description)

            # Here you can add functionality to send the data to an API or process it further
            st.success("Query sent successfully!")
        else:
            st.error("Please upload an image and provide a description.")

if __name__ == '__main__':
    main()