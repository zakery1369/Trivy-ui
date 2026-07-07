# Trivy Docker Image Scanner UI
![Trivy UI](https://raw.githubusercontent.com/zakery1369/pics/refs/heads/master/Trivy-UI.png)

یک رابط کاربری ساده، زیبا و فارسی برای اسکن امنیتی Docker Imageها با استفاده از [Trivy](https://github.com/aquasecurity/trivy).

این پروژه کمک می‌کند بدون نیاز به اجرای دستی دستورهای Trivy، ایمیج‌های Docker موجود روی سیستم را انتخاب کنید، ایمیج‌های ریموت را اسکن کنید، دیتابیس Trivy را به‌صورت دستی به‌روزرسانی کنید و خروجی گزارش را در فرمت‌های مختلف دریافت کنید.

---

## ویژگی‌ها

- رابط کاربری فارسی و راست‌چین
- نمایش نسخه Trivy داخل داشبورد
- انتخاب ایمیج از لیست Docker Image های موجود روی سیستم
- امکان وارد کردن نام/آدرس ایمیج ریموت مثل:

```bash
nginx:latest
alpine:3.19
python:3.12-slim
```

- اگر ایمیج روی سیستم وجود نداشته باشد، به‌صورت خودکار Pull می‌شود
- به‌روزرسانی دستی دیتابیس Trivy
- جلوگیری از آپدیت دیتابیس در هر اسکن با استفاده از دیتابیس موجود
- اسکن Docker Imageها با Trivy
- نمایش خلاصه آسیب‌پذیری‌ها بر اساس سطح شدت:
  - Critical
  - High
  - Medium
  - Low
  - Unknown
- فیلتر نتایج بر اساس Severity
- جستجو داخل نتایج اسکن
- خروجی گزارش در فرمت‌های مختلف:
  - HTML
  - JSON
  - SARIF
  - TXT
- استفاده از فونت فارسی Vazirmatn
- مناسب برای استفاده در محیط‌های DevOps / DevSecOps / Security Lab

---

## پیش‌نیازها

روی سیستم باید موارد زیر نصب باشد:

- Docker
- Docker Compose

برای بررسی نصب بودن Docker:

```bash
docker --version
docker compose version
```

---

## نصب و اجرا

ابتدا پروژه را کلون کنید:

```bash
git clone https://github.com/zakery1369/trivy-ui.git
cd trivy-ui-docker
```

سپس کانتینر را Build و اجرا کنید:

```bash
docker compose up -d --build
```

بعد از اجرا، UI از طریق آدرس زیر در دسترس است:

```text
http://localhost:8569
```

---

## اجرای مجدد پروژه

اگر تغییری در سورس پروژه دادید:

```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

---

## نحوه استفاده

### 1. انتخاب ایمیج از سیستم

در بخش انتخاب ایمیج، لیست Docker Imageهای موجود روی سیستم نمایش داده می‌شود.

لیست ایمیج‌ها به‌صورت خودکار هنگام باز شدن dropdown به‌روزرسانی می‌شود.

---

### 2. اسکن ایمیج ریموت

اگر ایمیج موردنظر روی سیستم وجود نداشته باشد، می‌توانید نام یا آدرس آن را وارد کنید.

مثال:

```bash
nginx:latest
ubuntu:22.04
redis:7
```

در صورت نبودن ایمیج روی سیستم، برنامه ابتدا آن را Pull کرده و سپس اسکن می‌کند.

---

### 3. به‌روزرسانی دیتابیس Trivy

برنامه به‌صورت پیش‌فرض در هر اسکن دیتابیس Trivy را آپدیت نمی‌کند.

برای آپدیت دیتابیس، از دکمه مخصوص به‌روزرسانی دیتابیس استفاده کنید.

این کار باعث می‌شود کنترل آپدیت دیتابیس در اختیار کاربر باشد و هر اسکن زمان اضافه برای آپدیت دیتابیس نگیرد.

---

### 4. دریافت خروجی گزارش

بعد از اتمام اسکن، می‌توانید گزارش را در یکی از فرمت‌های زیر دریافت کنید:

- HTML
- JSON
- SARIF
- TXT

---

## ساختار پروژه

```text
trivy-ui-zakops/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
├──trivy-cache
└── app/
    ├── main.py
    └── static/
        ├── index.html
        ├── styles.css
        ├── app.js
        ├── zak.png
        └── fonts/
            └── Vazirmatn.woff2
```

---

## نکته امنیتی مهم

این پروژه برای دسترسی به Docker Imageهای سیستم، Docker socket را داخل کانتینر mount می‌کند:

```yaml
- /var/run/docker.sock:/var/run/docker.sock
```

این دسترسی قدرتمند است و در محیط Production باید با احتیاط استفاده شود.

پیشنهاد می‌شود این ابزار فقط در محیط‌های کنترل‌شده مثل موارد زیر اجرا شود:

- سیستم شخصی
- محیط تست
- شبکه داخلی
- سرورهای DevOps کنترل‌شده
- Labهای امنیتی

---

## نمونه ایمیج برای تست

برای تست سریع می‌توانید از ایمیج‌های زیر استفاده کنید:

```bash
alpine:3.19
nginx:latest
ubuntu:22.04
redis:7
python:3.12-slim
```

---

## توقف برنامه

برای توقف سرویس:

```bash
docker compose down
```

---

## پاک‌سازی کامل

برای حذف کانتینرها و volumeها:

```bash
docker compose down -v
```

---

## درباره Trivy

Trivy یک ابزار متن‌باز برای اسکن امنیتی است که توسط Aqua Security توسعه داده شده و می‌تواند موارد زیر را بررسی کند:

- آسیب‌پذیری‌های OS Packageها
- آسیب‌پذیری‌های Libraryها
- Docker Imageها
- فایل‌سیستم
- Git Repository
- Kubernetes Manifest
- IaC Misconfiguration

---

## لینک‌ها

- GitHub: [zakery1369](https://github.com/zakery1369)
- Telegram: [Zakops](https://t.me/Zakops)
- Telegram: [DevOpsPersian](https://t.me/DevOpsPersian)
- Telegram: [DevOpsZakops](https://t.me/DevOpsZakops)
- Website: [zakops.com](https://zakops.com)

---

### Copyright (C) 2026 zakery1369
### SPDX-License-Identifier: AGPL-3.0-or-later
