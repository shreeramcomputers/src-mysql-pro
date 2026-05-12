# 🚀 SRC MySQL Pro Extension
**By Shree Ram Computers, Daurala, Meerut, Uttar Pradesh**

> **Deep Host se behtar Kodular/MIT App Inventor MySQL Extension**
> 100% Free · Secure · GitHub Actions se Online Build

---

## ⚡ Deep Host vs SRC MySQL Pro

| Feature | Deep Host | SRC MySQL Pro |
|---------|-----------|---------------|
| API Key exposed in APK | ⚠️ Haan, Risk | ✅ Nahi, HMAC use |
| Authentication | Plain API Key | HMAC Signature + Session Token |
| Replay Attack Protection | ❌ | ✅ Timestamp validation |
| Rate Limiting | ❌ | ✅ 120 req/hour |
| Pagination | Manual | ✅ Built-in (limit + offset) |
| Aggregate (COUNT/SUM/AVG) | Extra block | ✅ Built-in |
| JSON Helpers | Basic | ✅ GetValue, JsonToList, MakeJson, CSV |
| PHP Backend | Closed source | ✅ Open source + master.php |
| Price | 💰 Paid | 🆓 Free |
| SQL Injection Safe | Partial | ✅ Full PDO + Validation |

---

## 📁 Files

```
src-mysql-pro/
├── .github/workflows/build.yml     ← GitHub Actions (online build)
├── src/com/src/mysqlpro/
│   └── SRCMySQL.java               ← Extension code
├── php-backend/
│   └── src_mysql_api.php           ← PHP backend (upload to server)
├── aiwebres/
│   └── icon.png                    ← Extension icon
├── build.xml                       ← Ant build config
└── README.md                       ← Ye file
```

---

## 🛠️ Step-by-Step Setup

### Step 1: GitHub Repository Banayein

1. GitHub.com par account banayein (free hai)
2. **New Repository** banayein: `src-mysql-pro`
3. **Public** rakhen (free Actions ke liye)

### Step 2: Files Upload Karein

Ek-ek file GitHub par upload karein (ya ZIP upload karein):

```
Upload karein:
├── .github/workflows/build.yml
├── src/com/src/mysqlpro/SRCMySQL.java
├── build.xml
```

### Step 3: Automatic Build Dekhein

- Push karte hi **Actions tab** mein build start ho jaayega
- ✅ Green tick aane par **Artifacts** mein `SRCMySQLPro.aix` milega
- Download karein!

### Step 4: PHP Backend Setup

1. `php-backend/src_mysql_api.php` apne server par upload karein:
   ```
   Upload to: /public_html/api/src_mysql_api.php
   ```

2. File mein yeh line badlein:
   ```php
   define('SRCM_SECRET_KEY', 'APNA_32_CHARACTER_SECRET_KEY_YAHAN');
   ```
   Secret key example: `SRC2024Daurala@MysqlPro#SecureKey`

### Step 5: Kodular/App Inventor mein Use Karein

1. **Import Extension** → Download kiya hua `.aix` file
2. **ServerUrl** set karein: `https://yoursite.com/api/`
3. **SecretKey** set karein: (wahi jo PHP mein rakha)
4. App Start par `Authenticate("MyApp")` call karein
5. `OnAuthenticated` event mein aage kaam karein

---

## 💡 Block Examples (Kodular)

### App Initialize
```
When Screen1.Initialize
    Call SRCMySQL1.Authenticate("MyApp")

When SRCMySQL1.OnAuthenticated
    Label1.Text = "Connected! Token: " + sessionToken
    Call SRCMySQL1.GetAllRows("users", "id DESC", 20, 0, "load_users")

When SRCMySQL1.OnError
    Label1.Text = "Error: " + error
```

### User Register
```
When Button_Register.Click
    set dataJson to SRCMySQL1.MakeJson("name,mobile,city",
                    TextBox_Name.Text + "," +
                    TextBox_Mobile.Text + "," +
                    TextBox_City.Text)
    Call SRCMySQL1.InsertRow("users", dataJson, "register")

When SRCMySQL1.OnSuccess and callId = "register"
    set insertId to SRCMySQL1.GetInsertId(data)
    Notifier1.ShowAlert("Registered! ID: " + insertId)
```

### Search Users
```
When Button_Search.Click
    Call SRCMySQL1.LikeSearch(
        "users",              ← Table
        "name",               ← Column
        "%" + SearchBox.Text + "%",  ← Pattern
        20,                   ← Max results
        "search_users"        ← Call ID
    )

When SRCMySQL1.OnSuccess and callId = "search_users"
    set totalFound to SRCMySQL1.GetRowCount(data)
    set nameList to SRCMySQL1.JsonToList(data, "name")
    ListView1.Elements = nameList
```

### Count Users
```
Call SRCMySQL1.Aggregate("users", "*", "COUNT", "", "count_users")

When SRCMySQL1.OnSuccess and callId = "count_users"
    Label_Total.Text = "Total Users: " + SRCMySQL1.GetAggregateResult(data)
```

### Pagination (Load More)
```
# Page 1: offset=0, limit=10
Call SRCMySQL1.GetAllRows("products", "id DESC", 10, 0, "page1")

# Page 2: offset=10, limit=10
Call SRCMySQL1.GetAllRows("products", "id DESC", 10, 10, "page2")
```

---

## 🔒 Security Features

### HMAC Signature (Main Feature)
Har request mein ek secret signature hota hai:
```
signature = HMAC-SHA256(action + timestamp + secretKey, secretKey)
```
Matlab: Bina secret key ke koi bhi fake request nahi bhej sakta.

### Timestamp Validation
Purani requests (5 minute se zyada) automatically reject hoti hain.
Isse **replay attacks** band ho jaate hain.

### Session Token
Authentication ke baad ek temporary token milta hai (1 ghante ke liye).
Token expire hone par dobara authenticate karna hoga.

### Rate Limiting
Ek IP se zyada se zyada 120 requests/hour allowed hain.
Abuse nahi ho sakta.

---

## 🚀 New Release Kaise Nikaalein

1. GitHub → **Actions** tab
2. **Build SRC MySQL Pro Extension** → **Run workflow**
3. `release_tag` mein likhen: `v2.1.0`
4. **Run workflow** dabayein
5. Kuch minton mein **Releases** section mein `.aix` file ready!

---

## 📞 Support

**Shree Ram Computers**
Daurala, Meerut, Uttar Pradesh
Mobile: 9557283429
Website: shreeramcomputers.com
