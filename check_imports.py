try:
    from google.cloud.firestore_v1.field_path import FieldPath
    print("Found FieldPath in google.cloud.firestore_v1.field_path")
except ImportError:
    print("Not found in google.cloud.firestore_v1.field_path")

try:
    from google.cloud.firestore import FieldPath
    print("Found FieldPath in google.cloud.firestore")
except ImportError:
    pass

import google.cloud.firestore
print(f"google.cloud.firestore file: {google.cloud.firestore.__file__}")
