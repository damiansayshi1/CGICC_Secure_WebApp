
<h1>CGICC_Secure_WebApp</h1>

<h2>Description</h2>
<p>This website application is a CGI program written in C++ that can be used to create an account for a user or a service provider, and list things such as location, email, or role, that is all stored securely in MariaDB. Both clients and providers can see each other and send connection requests, which they can accept or reject. Both of these accounts have minimum privileges to ensure security, while an administrator account has access to modify anything.</p>
<br />

<p>The purpose of this project was to manually build the security features that protect a web application. By using C++ and the low-level CGICC library, I was able to implement defenses against common web threats from first principles, demonstrating a practical and deep understanding of web security concepts. </p>


<h2>Goals and Purpose</h2>
<ul>
<li><b>Implement Security from Scratch: </b>The goal was not just to build a website, but to build a secure one by hand-coding the defenses against threats defined by the Open Web Application Security Project (OWASP). </li>
<li><b>Understand the HTTP Lifecycle:</b>To manage the entire request/response cycle, including parsing headers, managing cookies for sessions, and generating HTML responses without the help of a framework.</li>
<li><b>Secure Database Interaction:</b>To connect to a MariaDB database and ensure all queries were safe from SQL injection by using prepared statements.</li>
</ul>
<br /><br />


<h2>Features</h2>
<ul>
<li><b>Secure User Authentication:</b> Passwords are never stored in plaintext. All user passwords are hashed using <b>SHA-256</b> before being stored and verified</li>
<li><b>Robust Session Management</b>: Employs signed cookies with a 5-minute expiry timer to manage user sessions and prevent unauthorized access</li>
<li><b>Role-Based Access Control (RBAC)</b>: Users are redirected to the login page if they attempt to access unauthorized routes (e.g., a client trying to access the admin dashboard)</li>
<li>Search and validation of IDs with custom string comparison</li>
<li><b>XSS & SQL Injection Mitigation</b>:
  <ul>
    <li>A custom `stop_xxs_function()` sanitizes all outputs to escape HTML/JS characters and prevent Cross-Site Scripting (XSS)</li>
    <li>Prepared Statements are used for all database queries to prevent SQL injection vulnerabilities.</li></ul></li>
<li><b>Proof-of-Concept 2FA & Admin Token</b>: Includes foundational logic for a Two-Factor Authentication system and a secondary Admin hardware token challenge</li>
</ul>
<br /><br/>


<h2>Technical Stack</h2>
<ul>
<li><b>Backend:</b> C++</li>
<li><b>Web Interface:</b> CGICC (C++ CGI Library) </li>
<li><b>Database:</b> MariaDB (with MariaDB Connector/C++) </li>
<li><b>Hashing:</b> `picoSHA2` library for SHA-256 implementation </li>
<li><b>Development Environment:</b> Linux/ GCC </li>
<br /><br/>






<p align="center">
What the 3 types of SQL databases look like: <br/>
<img src="https://i.imgur.com/XqcxRt2.png" height="80%" width="80%" alt="CGICC_website"/>
 <br />
<br />
  
Description of Connections database: <br/>
<img src="https://i.imgur.com/jvRxSR8.png" height="80%" width="80%" alt="CGICC_website"/>
<br />
<br />

Shows what providers have accepted or rejected connections: <br/>
<img src="https://i.imgur.com/lxDYb7s.png" height="80%" width="80%" alt="CGICC_website"/>
<br />
<br />

All values that are stored in the "Users" database: <br/>
<img src="https://i.imgur.com/8IsZSdt.png" height="80%" width="80%" alt="CGICC_website"/>
<br />
<br />

 Example of what the entered user input will look like: <br/> 
<img src="https://i.imgur.com/SBn3RD4.png" height="80%" width="80%" alt="CGICC_website"/>
<br />
<br />

 Description of Services Database: <br/> 
<img src="https://i.imgur.com/nRTXkPB.png" height="80%" width="80%" alt="CGICC_website"/>
<br />
<br />

Example of what the entered services input will look like: <br/> 
<img src="https://i.imgur.com/igNBZaJ.png" height="80%" width="80%" alt="CGICC_website"/>   
<br />
<br />


If the user gets their login information wrong, they will be notified and redirected to the login screen: <br/>
<img src="https://i.imgur.com/Zi73I3s.png" height="80%" width="80%" alt="CGICC_website"/>  
<br />
<br />

What the secure password hashes look like: <br/>
<img src="https://i.imgur.com/5QzYiwf.png" height="80%" width="80%" alt="CGICC_website"/>  
<br />
<br />

Code for escaping dangerous characters to avoid cross-site scripting: <br/>
<img src="https://i.imgur.com/cADX3PS.png" height="80%" width="80%" alt="CGICC_website"/>  
<br />
<br />

2FA check: <br/>
<img src="https://i.imgur.com/sifLAHg.png" height="80%" width="80%" alt="CGICC_website"/>  
<br />
<br />

Additional security check for an admin account: <br/>
<img src="https://i.imgur.com/x2LGxck.png" height="80%" width="80%" alt="CGICC_website"/>  
<br />
<br />

What values are held inside a cookie: <br/>
<img src="https://i.imgur.com/Row740N.png" height="80%" width="80%" alt="CGICC_website"/>  
<br />
<br />

Sessions will expire automatically after 5 minutes (handled by the cookie): <br/>
<img src="https://i.imgur.com/SQ07QWe.png" height="80%" width="80%" alt="CGICC_website"/>  
<br />
<br />
<br />
<h2>How to run:</h2>
<ol>
<li>Download the `.pkt` file from this repository.</li>
<li>Install Cisco Packet Tracer (https://www.netacad.com/courses/packet-tracer).</li>
<li>Open the `.pkt` file with Cisco Packet Tracer.</li>
<li>You can view all device configurations, run simulations (`ping`, etc.), and explore the network topology in detail.</li>
  
</ol>
</p>



