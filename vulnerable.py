from pathlib import Path
 
BASE_DIR = Path("files")
 
filename = input("Enter filename: ")
target = BASE_DIR / filename
 
with target.open("r", encoding="utf-8") as file:
    print(file.read())
