import face_recognition
from PIL import Image
import numpy as np

image_path = "test_face.jpg"

image = face_recognition.load_image_file(
    image_path
)

face_locations = face_recognition.face_locations(
    image
)

print(
    "Number of faces detected:",
    len(face_locations)
)

if len(face_locations) == 1:

    encoding = face_recognition.face_encodings(
        image,
        face_locations
    )[0]

    print(
        "Face encoding generated successfully."
    )

    print(
        "Encoding length:",
        len(encoding)
    )

else:

    print(
        "Please use an image containing exactly one face."
    )