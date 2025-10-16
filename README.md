# Cybersecurity scripts and tools

Its only for education purposes.

## Scripts
- [check_passw_sec_model.py](./check_passw_sec_model.py) Simple AI model to check if a password is secure.
- [secNotes.py](./secNotes.py) Data confidentiality and integrity with GUI. To encrypt/decrypt text notes (e.g. passwords).
- [secImgs.py](./secImgs.py) Data confidentiality and integrity with GUI. It was designed for images but it can encrypt/decrypt all types of files.
- [sniffer.py](./sniffer.py) Simple packet sniffer.
- [password_generator.py](./password_generator.py) Generate all possible combinations/permutations from user preference/data. ex: favorite date, favorite films, name, etc.

## Methods
<!--- Windows --->
<details closed>
<summary><b>Windows: login bypass in less than 3min. </b></summary>
Execute the following commands.
<br>
  
```cmd
to do
```
</details>

<!--- Windows --->
<details closed>
<summary><b>Windows: get wifi saved passwords from a terminal</b></summary>
Execute the following command:
<br>

```cmd
netsh wlan show profiles
```
choose the profile of interest, then:
```cmd
netsh wlan show profile name=<ProfileName> key=clear
```
</details>

<!--- Windows --->
Windows: [VBS scripting](./VBScripts)


## Guides 
[guides](./guides]

<br>

## Creating an executable
```bash
pip install pyinstaller
```
```bash
pyinstaller --onefile --name exec_name source_script.py
```
![sec-tools](./ypcUniform.jpg)
