## **VetVibes - Veterinary Store E-Commerce Website**   
### **An Online Store for Domestic Animal Medicines**  
### **Features**  
- **User Authentication** (Sign-up & Login)  
- **Browse & Add Products to Cart**  
- **Secure Checkout with Order Saving**  
- **Order Summary & Confirmation**  
- **Fast & Responsive UI**
## **Getting Started**  
### **1️ Clone the Repository**  
Open a terminal and run:  
git clone https://github.com/Yuvam007/VetVibes.git
cd VetVibes
### **2️ Install Dependencies**  
Run the following command to install required Node.js packages:  
npm install
### **3️ Set Up Environment Variables**  
Create a `db.env` file in the root directory and add:  
```env
MONGO_URI=mongodb://localhost:27017/VetVibes
PORT=3000
```
If you're using **MongoDB Atlas**, replace `MONGO_URI` with your actual cloud database connection string.  

### **4️ Start MongoDB**  
- If using **local MongoDB**, start it with:  
  mongod
- If using **MongoDB Atlas**, ensure your connection string is correct in `db.env`.
### **5️ Start the Server**  
Run the following command to start the backend server:  

node server.js

Your server should now be running at **http://localhost:3000**  

---
## **Frontend**  
- The frontend is built with **HTML, CSS, and JavaScript**.  
- Make sure the frontend correctly makes calls to the backend server at `http://localhost:3000`.

---

## **Contributors**  
**[Yuvam Tougani]** - Developer
Email: yuvam.tougani@bcah.christuniversity.in  

---
