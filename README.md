This is executed with the command:

python sync_access_policies.py --config config.txt

in which config.txt is a YAML file with the entries:


```
customer_id: <ZPA tenant ID>
client_id: <ZPA API client ID>
client_secret: <ZPA client secret>
target: <target Microtenant name>
skiplist:
- "Default"
- <other tenants to not include in source Access Policy sync to target>
```
