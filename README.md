# Cybersecurity scripts and tools

Its only for education purposes.

## Scripts
- [check_passw_sec_model.py](./check_passw_sec_model.py) Simple AI model to check if a password is secure.
- [secNotes.py](./secNotes.py) Data confidentiality and integrity with GUI. To encrypt/decrypt text notes.
- [secImgs.py](./secImgs.py) Data confidentiality and integrity with GUI. It was designed for images but it can encrypt/decrypt all types of files.
- [sniffer.py](./sniffer.py) Simple packet sniffer.
- [password_generator.py](./password_generator.py) Generate all possible combinations/permutations from user preference/data. ex: favorite date, favorite films, name, etc.

## Methods
<!--- Windows --->
<details closed>
<summary><b>Windows: login bypass in less than 3 min (to do).</b></summary>
</details>
<details closed>
<summary><b>Windows: get wifi password from a terminal</b></summary>
```cmd
netsh wlan show profiles
```
```cmd
netsh wlan show profile name="ProfileName" key=clear
```
</details>
  
## Creating an executable
```bash
pip install pyinstaller
```
```bash
pyinstaller --onefile --name exec_name source_script.py
```
![sec-tools](./ypcUniform.jpg)
