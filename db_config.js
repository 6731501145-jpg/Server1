const mysql = require('mysql2');
 
// pool + promise: ใช้ await con.query(...) ได้ และใช้ con.getConnection() ทำ transaction ได้
const con = mysql
  .createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'mfu_student_assignment_tracking', // ชื่อ DB จาก schema.sql
    waitForConnections: true,
    connectionLimit: 10,
    charset: 'utf8mb4',
  })
  .promise();
 
module.exports = con;
