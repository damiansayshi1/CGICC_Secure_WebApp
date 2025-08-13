#include <iostream>
#include <mariadb/conncpp.hpp>
#include <cgicc/HTTPHTMLHeader.h>
#include <cgicc/Cgicc.h>
#include <cgicc/HTTPCookie.h>
#include <picosha2.h>
#include <string>
 #include <fstream>     
 #include <random>
 //*Please note, use 000000 to bypass 2FA authentication and 1234563510 to bypass admin hardware token challenge response. 
 //This is all the includes that I am using in this code for this secure website. 
        cgicc::Cgicc cgi;
            
        
 // XSS prevention function- this basically escapes dangerous characters in user input, like HTML of JS. This follows OWASP recommendations for output encoding       
std::string stop_xxs_function(const sql::SQLString& data) {
            std::string escaped;
            std::string str_data = static_cast<std::string>(data);
        for (char c : str_data) {
            switch (c) {
                case '&': escaped += "&amp;"; break;
                case '<': escaped += "&lt;"; break;
                case '>': escaped += "&gt;"; break;
                case '"': escaped += "&quot;"; break;
                case '\'': escaped += "&#39;"; break;
                case '(': escaped += "&#40;"; break;
                case ')': escaped += "&#41;"; break;
                case ';': escaped += "&#59;"; break;
            default: escaped += c;
        }
    }// Input sanitization as reccomended by OWASP 
    return escaped;
}
            //I used this function to automate the header being printed in the same format every time, and this include XXS protection for the title. This is cleaner than writing out the header with every response. 
void print_html_header(const std::string& title) {
            std::cout << cgicc::HTTPContentHeader("text/html; charset=utf-8") << std::endl;
            std::cout << "<!DOCTYPE html>" << std::endl;
            std::cout << "<html lang='en'>" << std::endl;
            std::cout << "<head>" << std::endl;
            std::cout << "<meta charset='UTF-8'>" << std::endl;
            std::cout << "<title>" << stop_xxs_function(title) << "</title>" << std::endl;
            std::cout << "<link rel='stylesheet' type='text/css' href='/secure_website.css'>" << std::endl;
            std::cout << "</head>" << std::endl;
            std::cout << "<body>" << std::endl;
}

void show_user_edit_form(std::shared_ptr<sql::Statement> stmnt, int target_user_id, int current_user_id, const std::string& current_role);

void update_user(std::shared_ptr<sql::Statement> stmnt, int target_user_id, int current_user_id, const std::string& current_role);

void simulate_email_sending(const std::string& email, const std::string& code);
            
// This function creates a secure session cookie with user details by using their user_id, role, username and hash
void set_session_cookie(int user_id, const std::string& role, const std::string& username) {
            std::string cookie_value = std::to_string(user_id) + "|" + role + "|" + username + "|" + picosha2::hash256_hex_string(std::to_string(user_id) + role + username + "Damian_extra_salt");
            cgicc::HTTPCookie session_cookie("Damian_Session", cookie_value);
            session_cookie.setPath("/");
            session_cookie.setMaxAge(60 * 5); 
                std::cout << cgicc::HTTPHTMLHeader().setCookie(session_cookie);
}
 //Validates session by checking if the cookie actually exists, has correct format and matches the hash. This returns user details if correct.
bool validate_session(int& user_id, std::string& role, std::string& username) {
            const cgicc::CgiEnvironment& env = cgi.getEnvironment();
            std::string cookie_value;
    
        for (auto it = env.getCookieList().begin(); it != env.getCookieList().end(); ++it) {
            if (it->getName() == "Damian_Session") {
                cookie_value = it->getValue();
            break;
        }
    }
        if (cookie_value.empty()) {
        return false;
    }
            std::vector<std::string> parts;
            size_t start = 0;
            size_t end = cookie_value.find('|');
    
        while (end != std::string::npos) {
            parts.push_back(cookie_value.substr(start, end - start));
            start = end + 1;
            end = cookie_value.find('|', start);
    }
            parts.push_back(cookie_value.substr(start));

        if (parts.size() != 4) {
        return false;
    }

        try {
            user_id = std::stoi(parts[0]);
            role = parts[1];
            username = parts[2];
            std::string received_hash = parts[3];
        
            std::string expected_hash = picosha2::hash256_hex_string(
            std::to_string(user_id) + role + username + "Damian_extra_salt");
        
        if (received_hash != expected_hash) {
        return false;
        }
        return true;
    } catch (...) {
        return false;
    }
}
// this displays some of the SQL data to the users, including data about the actual user.
void display_users_function(std::shared_ptr<sql::Statement> &stmnt){
            std::unique_ptr<sql::ResultSet> res(
            stmnt->executeQuery("SELECT User_id, first_name, last_name, email, username, role, location FROM Connections_Website_Damian.Users"));
            std::cout << "<table border='1'>";
            std::cout << "<tr><th>User_id</th><th>first_name</th><th>last_name</th><th>email</th><th>username</th><th>role</th><th>location</th></tr>";
        while (res->next()){
            std::cout << "<tr>";
            std::cout <<"<td>"<< stop_xxs_function(std::to_string(res->getInt("User_id")))<<"</td>";         
            std::cout <<"<td>"<< stop_xxs_function(static_cast<std::string>(res->getString("first_name")))<<"</td>";
            std::cout<< "<td>"<<stop_xxs_function(static_cast<std::string>(res->getString("last_name")))<<"</td>";
            std::cout << "<td>"<<stop_xxs_function(static_cast<std::string>(res->getString("email")))<<"</td>";
            std::cout << "<td>"<<stop_xxs_function(static_cast<std::string>(res->getString("username")))<<"</td>";           
            std::cout << "<td>"<<stop_xxs_function(static_cast<std::string>(res->getString("role")))<<"</td>";
            std::cout << "<td>"<<stop_xxs_function(static_cast<std::string>(res->getString("location")))<<"</td>"<< "</tr>" ;            
      }
      std::cout << "</table>";
            }
            //displays SQL table on the connections and what has been initiated, accepted and rejected
void display_connections_table(std::shared_ptr<sql::Statement> &stmnt){
            std::unique_ptr<sql::ResultSet> res(
            stmnt->executeQuery("SELECT connection_id, client_id, provider_id, status FROM Connections_Website_Damian.Connections"));   
            
            std::cout << "<table border='1'>";
            std::cout << "<tr><th>Connection Id</th><th>Client Id</th><th>Provider Id</th><th>Status </th></tr>";
      while (res->next()){
            std::cout << "<tr>";
            std::cout <<"<td>"<< stop_xxs_function(std::to_string(res->getInt("connection_id")))<<"</td>";         
            std::cout <<"<td>"<< stop_xxs_function(static_cast<std::string>(res->getString("client_id")))<<"</td>";
            std::cout<< "<td>"<<stop_xxs_function(static_cast<std::string>(res->getString("provider_id")))<<"</td>";
            std::cout << "<td>"<<stop_xxs_function(static_cast<std::string>(res->getString("status")))<<"</td>";         
            std::cout << "</tr>" << "</table>";
}}
//shows what providers there is
void display_services_table(std::shared_ptr<sql::Statement> &stmnt){
            std::unique_ptr<sql::ResultSet> res(
            stmnt->executeQuery("SELECT service_id , service_type, provider_id, provider_location, description, is_active FROM Connections_Website_Damian.Services"));

            std::cout << "<table border='1'>";
            std::cout << "<tr><th>Service ID</th><th>Service Type</th><th>Provider ID</th><th>Provider Location</th><th>description</th><th>Is active?</th></tr>";
      while (res->next()){
            std::cout << "<tr>";
            std::cout <<"<td>"<< stop_xxs_function(std::to_string(res->getInt("service_id")))<<"</td>";         
            std::cout <<"<td>"<< stop_xxs_function(static_cast<std::string>(res->getString("service_type")))<<"</td>";
            std::cout<< "<td>"<<stop_xxs_function(static_cast<std::string>(res->getString("provider_id")))<<"</td>";
            std::cout << "<td>"<<stop_xxs_function(static_cast<std::string>(res->getString("provider_location")))<<"</td>";
            std::cout << "<td>"<<stop_xxs_function(static_cast<std::string>(res->getString("description")))<<"</td>";           
            std::cout << "<td>"<<stop_xxs_function(static_cast<std::string>(res->getString("is_active")))<<"</td>";;            
            std::cout << "</tr>" ;          
      }
      std::cout << "</table>";
            }
            //this is extra security to ensure that admin is properly authenticated. In real life this would use a more robust sytem.
void admin_vertification_portal(std::shared_ptr<sql::Statement> stmnt){

              std::string admin_entered_password2 = cgi("admin_entered_password"); 
              std::string stored_admin_password2="1234563510";  
              if (admin_entered_password2 == stored_admin_password2){
              print_html_header("Admin Login Success");
              std::cout<< "<h1>Congrats, admin status has been aproved. Continue again to main site</h1>"
                     << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
                     << "<input type='submit' name='action' value='Continue to Admin Dashboard'>"
                     << "</form></body></html>";    
        } else{
              print_html_header("Admin Login Failure");
            std::cout<< "<h1>Sorry, but the admin secondary password is incorrect. You will be asked to go back to the login page.</h1>"
            << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
            << "<input type='submit' name='action' value='login_page'>"
            << "</form></body></html>";    
            }
}

std::string generate_2fa_code() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(100000, 999999);
    return std::to_string(dis(gen));
}

void store_2fa_code(std::shared_ptr<sql::Statement> stmnt, int user_id, const std::string& code) {
    try {
        std::unique_ptr<sql::PreparedStatement> pstmt(
            stmnt->getConnection()->prepareStatement(
                "UPDATE Users SET two_fa_code = ?, two_fa_expiry = DATE_ADD(NOW(), INTERVAL 5 MINUTE) WHERE User_id = ?"));
        pstmt->setString(1, code);
        pstmt->setInt(2, user_id);
        pstmt->executeUpdate();
        
        std::unique_ptr<sql::PreparedStatement> emailStmt(
            stmnt->getConnection()->prepareStatement(
                "SELECT email FROM Users WHERE User_id = ?"));
        emailStmt->setInt(1, user_id);
        std::unique_ptr<sql::ResultSet> res(emailStmt->executeQuery());
        
        if (res->next()) {
            std::string email = static_cast<std::string>(res->getString("email"));
            simulate_email_sending(email, code);
        }
    } catch (sql::SQLException& e) {
    }
}

void verify_2fa(std::shared_ptr<sql::Statement> stmnt, int user_id, const std::string& role, const std::string& username) {
    std::string entered_code = cgi("two_fa_code");

        if (entered_code == "000000") {

        set_session_cookie(user_id, role, username);
                        if (role == "admin") {
                    print_html_header("Admin Login Success");
                    std::cout << "<h1>Your initial password and 2FA has been validated, but since you are an admin, you will have to enter your challenge response.</h1>"
                              << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
                              << "Admin Secondary Password: <input type='password' name='admin_entered_password'><br>"                     
                              << "<input type='submit' name='action' value='Continue to Challenge Response Portal'>"
                              << "</form></body></html>";}
                              else {
        print_html_header("Bypassed 2FA");
                              std::cout<< "<h1>2FA validated. Click the button below to go to main dashboard</h1>"
                              << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
                              << "<input type='submit' name='action' value='Continue to Site'>"
                              << "</form></body></html>";;                 
                              }
    try {
        std::unique_ptr<sql::PreparedStatement> pstmt(
            stmnt->getConnection()->prepareStatement(
                "SELECT two_fa_code FROM Users WHERE User_id = ? AND two_fa_expiry > NOW()"));
        pstmt->setInt(1, user_id);
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        
        if (res->next()) {
std::string stored_code = static_cast<std::string>(res->getString("two_fa_code"));
            
            if (entered_code == stored_code) {
                std::unique_ptr<sql::PreparedStatement> clearStmt(
                    stmnt->getConnection()->prepareStatement(
                        "UPDATE Users SET two_fa_code = NULL, two_fa_expiry = NULL WHERE User_id = ?"));
                clearStmt->setInt(1, user_id);
                clearStmt->executeUpdate();
                
                set_session_cookie(user_id, role, username);
                
                if (role == "admin") {
                    print_html_header("Admin Login Success");
                    std::cout << "<h1>Your initial password has been validated, but since you are an admin, you will have to enter your challenge response.</h1>"
                              << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
                              << "Admin Secondary Password: <input type='password' name='admin_entered_password'><br>"                     
                              << "<input type='submit' name='action' value='Continue to Challenge Response Portal'>"
                              << "</form></body></html>";
                } else {
                    std::cout << "<html><head><title>Login Success</title>"
                              << "<link rel='stylesheet' type='text/css' href='/secure_website.css'>"
                              << "</head><body>"
                              << "<h1>Credentials validated. Click the button below to continue to the main site.</h1>"
                              << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
                              << "<input type='submit' name='action' value='Continue to Site'>"
                              << "</form></body></html>";
                }
            } 
        } else {
            print_html_header("2FA Error");
            std::cout << "<h1>2FA code expired or not found</h1>"
                      << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
                      << "<input type='submit' name='action' value='Try Again'>"
                      << "</form></body></html>";
        }
    } catch (sql::SQLException& e) {
        print_html_header("System Error");
        std::cout << "<h1>Error verifying 2FA code</h1>"
                  << "<a href='?action=login_page'>Please try again</a></body></html>";
    }
}else{
                print_html_header("2FA Error");
            std::cout << "<h1>2FA code expired or not found</h1>"
                      << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
                      << "<input type='submit' name='action' value='Try Again'>"
                      << "</form></body></html>";
}}


void proccess_login(std::shared_ptr<sql::Statement> stmnt) {
            std::string user_entered_username = cgi("username");
            std::string user_entered_password = cgi("password");         
    
        try {
            std::unique_ptr<sql::PreparedStatement> pstmt(
            stmnt->getConnection()->prepareStatement(
            "SELECT User_id, role, password_hash FROM Users WHERE username = ?"));
            pstmt->setString(1, user_entered_username);
                
            std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
         
        if (!res->next()) { 
            print_html_header("Login Error");
            std::cout<< "<h1>Error: Invalid Login Credentials (Either Username/ Password or both are wrong)</h1>"
            << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
            << "<input type='submit' name='action' value='Try Again'>"
            << "</form></body></html>";
        return;
        }
        
            int user_id = res->getInt("User_id");
            std::string stored_role = static_cast<std::string>(res->getString("role"));        
            std::string stored_hash = static_cast<std::string>(res->getString("password_hash"));
            std::string input_hash = picosha2::hash256_hex_string(user_entered_password);         
         
        if (stored_hash == input_hash) {
            set_session_cookie(user_id, stored_role, user_entered_username);
            
            if(stored_role == "admin") {           
            print_html_header("Admin Login Success");
            std::cout<< "<h1>Your initial password has been validated, but since you are an admin, you will have to enter your challenge response. (If you did not recieve a challenge response code, please refer to the README.txt to see a valid admin challenge response token that you can use, or refer to begining of my report on page 3 for the code.)</h1>"
            << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
            << "Admin Secondary Password: <input type='password' name='admin_entered_password'><br>"                     
            << "<input type='submit' name='action' value='Continue to Challenge Response Portal'>"
            << "</form></body></html>";
    } else {
            std::cout << "<html><head><title>Login Success</title>"
            << "<link rel='stylesheet' type='text/css' href='/secure_website.css'>"
            << "</head><body>"
            << "<h1>Credentials validated. Click the button below to continue to the main site.</h1>"
            << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
            << "<input type='submit' name='action' value='Continue to Site'>"
            << "</form></body></html>";
            }
        } else {
            print_html_header("Login Error");
            std::cout<< "<h1>Error: Invalid Login Credentials (Either Username/ Password or both are wrong)</h1>"
            << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
            << "<input type='submit' name='action' value='Try Again'>"
            << "</form></body></html>";
        }
    }
        catch (sql::SQLException& e) {
            print_html_header("System Error");
            std::cout<< "<h1>Login Error: Please try again later</h1>"
            << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
            << "<input type='submit' name='action' value='Return to Login'>"
            << "</form></body></html>";
    }}
         //password is required to be 10 characters, with lowercase, uppercase, number and a special character.
bool validate_password_function_registration(const std::string& password){
            if (password.length() < 10) return false;
            bool has_lower = false, has_upper = false, has_digit = false, has_special = false;
            for (char ch : password) {
            if (islower(ch)) has_lower = true;
            else if (isupper(ch)) has_upper = true;
            else if (isdigit(ch)) has_digit = true;
            else if (ispunct(ch)) has_special = true;
    }
        return has_lower && has_upper && has_digit && has_special;
}
 //this simulates sending emails, but tries to write to a .txt file, which can be opened by user to see the 2FA code. In real life this would connect to a STMP server.
void simulate_email_sending(const std::string& email, const std::string& code) {
    try {
        std::ofstream mail_spool("Damian_mail_spoof.txt", std::ios::app);
        if (!mail_spool.is_open()) {
            mail_spool.open("/tmp/Damian_mail_spoof.txt", std::ios::app);
            if (!mail_spool.is_open()) {
                return;
            }
        }
        mail_spool << "To: " << email << "\n"
                   << "Subject: Your 2FA Code\n"
                   << "Body: Your verification code is: " << code << "\n\n";
        mail_spool.close();
    } catch (const std::exception& e) {
    }
}
            //this handles the registration of new users
void proccess_registration(std::shared_ptr<sql::Statement> stmnt) {      
            std::string first_name = cgi("first_name");
            std::string last_name = cgi("last_name");
            std::string email = cgi("email");
            std::string username = cgi("username");
            std::string role = cgi("role");
            std::string location = cgi("location");            
            std::string password = cgi("password");   
        if(username.length() > 25 || first_name.length() > 25 || last_name.length() > 25 || email.length() > 100 || location.length() > 50 ){
            print_html_header("Inputs too long");
            std::cout << "<html><body><h1>Sorry, but user inputs are too long. Name/ username must be less than 25 characters, email must be under 100 characters and location must be below 50 characters.</h1>";
        return; 
            }
            
        if (!validate_password_function_registration(password)){
            print_html_header("Registration Error");
            std::cout << "<h1>Sorry, but password did not match the requirements.</h1>";
            std::cout << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>";
            
            std::cout << "<p>Sorry but password was not accepted.<p><br>";
            std::cout << "<p>10 characters minimum, including lowercase, uppercase, special character and number<p><br>";
            std::cout << "<p>Please choose if you want to go back to the login screen or the registration screen to try again<p><br>";
            std::cout << "<input type='submit' name='action' value='Login'><br>";
            std::cout << "<input type='submit' name='action' value='Register'><br>";
            std::cout << "</form>";
            std::cout << "</body></html>";
        return;
            }
            
           std::string password_hash = picosha2::hash256_hex_string(password);
        try{
            std::unique_ptr<sql::PreparedStatement> pstmt(
            stmnt->getConnection()->prepareStatement("INSERT INTO Users (first_name, last_name, email, username, role, location, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?)"));
            pstmt->setString(1, first_name);
            pstmt->setString(2, last_name);        
            pstmt->setString(3, email);
            pstmt->setString(4, username);
            pstmt->setString(5, role);
            pstmt->setString(6, location);
            pstmt->setString(7, password_hash);       
            pstmt->executeUpdate();          
            print_html_header("Succesful Account Registration");
         
            std::cout << "<h1>Account Created Successfully!</h1>";
            std::cout << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>";         
            std::cout << "<input type='submit' name='action' value='Login'><br>";
            std::cout << "</body></html>";
           }
        catch (const sql::SQLException& e){
            print_html_header("Registration Error");
            
            std::cout << "<h1>Password did not match requirements</h1>";
            std::cout << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>";
            std::cout << "<p>Sorry but there was an error creating your account<p><br>";
            std::cout << "<input type='submit' name='action' value='Login'><br>";
            std::cout << "<input type='submit' name='action' value='Register'><br>";
            std::cout << "</form>";
            std::cout << "</body></html>";
   }
            }
            
void create_user(){
            print_html_header("User Registration");
            std::cout << "<h1>Create a new Account</h1>";
            std::cout << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>";
            std::cout << "<label for='first_name'>First Name:</label>";
            std::cout << "<input type='text' id='first_name' name='first_name' required><br>";           
            std::cout << "<label for='last_name'>Last Name:</label>";
            std::cout << "<input type='text' id='last_name' name='last_name' required><br>";           
            std::cout << "<label for='email'>Email:</label>";
            std::cout << "<input type='text' id='email' name='email' required><br>";            
            std::cout << "<label for='username'>Username:</label>";
            std::cout << "<input type='text' id='username' name='username' required><br>";     
            std::cout << "<label for='password'>Password:</label>";
            std::cout << "<input type='password' id='password' name='password' required><br>";
            std::cout << "<small>10 characters minimum, including lowercase, uppercase, special character and number</small><br>";           
            std::cout << "<label for='role'>Role:</label>";
            std::cout << "<select id='role' name='role' required>";
            std::cout << "<option value='admin'>admin</option>";
            std::cout << "<option value='service_provider'>service provider</option>";
            std::cout << "<option value='client'>client</option>";
            std::cout << "</select><br>";
            std::cout << "<label for='location'>Location:</label>";
            std::cout << "<input type='text' id='location' name='location' required><br>";     
            std::cout << "<input type='submit' name='action' value='Register Account'><br>";       
            std::cout << "<input type='submit' name='action' value='Return to Login Page'><br>";  
            std::cout << "</form>";
            std::cout << "</body></html>";
    }

void login_page (){

            print_html_header("Login Page");
            std::cout << "<h1>Login to Your Account</h1>";
            std::cout << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>";
            std::cout << "Username: <input type='text' name='username'><br>";
            std::cout << "Password: <input type='password' name='password'><br>";
            std::cout << "<input type='submit' name='action' value='Login'><br>";
            std::cout << "<input type='submit' name='action' value='Register'><br>";
            std::cout << "</form>";
            std::cout << "</body></html>";
}            

bool is_cookie_present_function() {
            const cgicc::CgiEnvironment& env = cgi.getEnvironment();
        for (cgicc::const_cookie_iterator it = env.getCookieList().begin(); 
            it != env.getCookieList().end(); ++it) {
        if (it->getName() == "Damian_Cookie") {
        return true;
        }
    }
        return false;
}
                


void dashboard(std::shared_ptr<sql::Statement> &stmnt) {
        try {
            int user_id;
            std::string role, username;
        
        if (!validate_session(user_id, role, username)) {
            print_html_header("Session Expired");
            std::cout << "<html><body><h1>Session expired or invalid</h1>"
                      << "<a href='?action=login_page'>Please login again</a></body></html>";
            return;
        }
        
            print_html_header("Main Dashboard");
            std::cout<< "<h3>Welcome, " << stop_xxs_function(username) << "!</h3>"
            << "<h3>Search Services</h3>"
            << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
            << "Type: <input type='text' name='service_type'><br>"
            << "Location: <input type='text' name='location'><br>"
            << "<input type='submit' name='action' value='Search'>"
            << "</form>"
            << "<p>You are currently logged in as: " << stop_xxs_function(role) << "<p><br>";
        
        if (role == "admin") {
            std::cout << "<h1>Users that have signed up with this platform</h1>";  
            display_users_function(stmnt);
}        
            std::cout << "<h1><br>Here is a table with all the current connections<br></h1>";
            display_connections_table(stmnt);         
            std::cout << "<h1><br>All the different services provided<br></h1>";
            display_services_table(stmnt);              
            std::cout << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
            << "<input type='submit' name='action' value='logout'>Logout</input><br>"
            << "</form>"
            << "<p>Your session will terminate and you will be logged out in 5 minutes.<p><br>"            
            << "</body></html>";
    }
        catch (sql::SQLException& e) {
            std::cout << "<html><body><h1>Error loading dashboard</h1>"
            << "<a href='?action=login_page'>Please login again</a></body></html>";
    }
}
void logout() {
            std::cout << cgicc::HTTPContentHeader("text/html; charset=utf-8") << std::endl;
            cgicc::HTTPCookie cookie("Damian_Session", "");
            cookie.setPath("/");
            cookie.setMaxAge(0);  
            std::cout << cookie << std::endl;
            print_html_header("Logout Successful");
            std::cout << "<h1>Logged out successfully</h1>"
            << "<a href='?action=login_page'>Login again</a>";
}
   
void search_services(std::shared_ptr<sql::Statement> &stmnt) {
            std::string service_type = cgi("service_type");
            std::string location = cgi("location");
            print_html_header("Search Services");
            std::cout<< "<h1>Search Results</h1>";
    try {
            std::string query = "SELECT * FROM Services WHERE 1=1 ";
        if (!service_type.empty()) {
            query += "AND service_type LIKE '%" + service_type + "%' ";
        }
        if (!location.empty()) {
            query += "AND provider_location LIKE '%" + location + "%' ";
        }

            std::unique_ptr<sql::ResultSet> res(stmnt->executeQuery(query));

            std::cout << "<table border='1'><tr>"
            << "<th>Type</th><th>Location</th><th>Description</th><th>Action</th></tr>";

        while (res->next()) {
                std::cout << "<tr>"
                << "<td>" << res->getString("service_type") << "</td>"
                << "<td>" << res->getString("provider_location") << "</td>"
                << "<td>" << res->getString("description") << "</td>"
                << "<td><form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
                << "<input type='hidden' name='service_id' value='" 
                << res->getInt("service_id") << "'>"
                << "<input type='submit' name='action' value='Request Service'>"
                << "</form></td>"
                << "</tr>";
        }
                std::cout << "</table></body></html>";

    } catch (sql::SQLException& e) {
    }
}

void request_service_function(std::shared_ptr<sql::Statement> &stmnt) {
                int service_id = std::stoi(cgi("service_id"));
                int client_id = 1;
            try {
                stmnt->execute("INSERT INTO Connections (client_id, provider_id, status) "
                "SELECT " + std::to_string(client_id) + ", provider_id, 'pending' "
                "FROM Services WHERE service_id=" + std::to_string(service_id));

print_html_header("Request Sent");
                 std::cout<< "<p>Request sent!</p>"
                 << "<a href='?action=dashboard'>Back to dashboard</a>"
                 << "</body></html>";

    }   catch (sql::SQLException& e) {
    }
}
    //dashboard for admin with extra permissions, like seeing everyones records and being able to edit anyone
void admin_dashboard(std::shared_ptr<sql::Statement> &stmnt) {
        try {
            int user_id;
            std::string role, username;
        if (!validate_session(user_id, role, username) || role != "admin") {
            std::cout << "Location: /login_page\r\n\r\n"; 
        return;
        }
            std::cout << cgicc::HTTPContentHeader("text/html; charset=utf-8") << std::endl;
            print_html_header("Admin Dashboard");
            std::cout << "<p>You are currently logged into the admin portal, which has elevated privileges to create new accounts and set up passwords and email addresses on them.</p><br>";             
            std::cout << "<h1>Users that have signed up with this platform</h1>";  
            display_users_function(stmnt);
        
            std::cout << "<h1><br>Here is a table with all the current connections<br></h1>";
            display_connections_table(stmnt);         
            std::cout << "<h1><br>All the different services provided<br></h1>";
            display_services_table(stmnt);              
            std::cout << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
            << "<input type='submit' name='action' value='Return to Login Page'><br>"
            << "</form>"
            << "<h1>Admin actions: Create User</h1>"
            << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
            << "<input type='submit' name='action' value='Register a new user'><br>"
            << "</form>"
            << "<h1>Admin actions: Modify a User's records</h1>"
            << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
            << "<input type='submit' name='action' value='Modify a user'><br>"
            << "</form>"
            << "<p>Your session will terminate and you will be logged out in 5 minutes.</p>";
    }
    catch (sql::SQLException& e) {
            print_html_header("System Error");
            std::cout << "<h1>Error loading dashboard</h1>"
            << "<a href='?action=dashboard'>Try again</a>";
    }
}   
   //admin can modify anyone, but user can only modify themselves
void modify_a_user_function(std::shared_ptr<sql::Statement> stmnt) {
            print_html_header("Modify a User");
            int current_user_id;
            std::string current_role, current_username;
        if (!validate_session(current_user_id, current_role, current_username)) {
            std::cout << "<h1>Session expired</h1>"
            << "<a href='?action=login_page'>Please login again</a></body></html>";
    return;
    }

    if (cgi("action") == "Modify a user") {
        if (current_role == "admin") {
            display_users_function(stmnt);
            std::cout << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
            << "Enter User ID to edit: <input type='text' name='target_user_id' required><br>"
            << "<input type='submit' name='action' value='Edit User'>"
            << "</form>";
    } else {
            show_user_edit_form(stmnt, current_user_id, current_user_id, current_role);
        }
    } 
    else if (cgi("action") == "Edit User") {
            int target_user_id = std::stoi(cgi("target_user_id"));
            show_user_edit_form(stmnt, target_user_id, current_user_id, current_role);
    }
    else if (cgi("action") == "Save User Changes") {
            int target_user_id = std::stoi(cgi("target_user_id"));
            update_user(stmnt, target_user_id, current_user_id, current_role);
    }
    else {
            std::cout << "<h1>Invalid action</h1>"
            << "<a href='?action=dashboard'>Back to dashboard</a></body></html>";
    }
}
void show_user_edit_form(std::shared_ptr<sql::Statement> stmnt, int target_user_id, int current_user_id, const std::string& current_role) {
            print_html_header("User Edit Form");
        try { 
        if (current_role != "admin" && target_user_id != current_user_id) {
            std::cout << "<h1>Error: You can only edit your own profile</h1>"
                      << "<a href='?action=dashboard'>Back to dashboard</a></body></html>";
        return;
        }
            std::unique_ptr<sql::PreparedStatement> pstmt(
            stmnt->getConnection()->prepareStatement(
            "SELECT first_name, last_name, email, username, role, location FROM Users WHERE User_id = ?"));
            pstmt->setInt(1, target_user_id);
        
            std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
        
        if (!res->next()) {
            std::cout << "<h1>Error: User not found</h1>"
            << "<a href='?action=dashboard'>Back to dashboard</a></body></html>";
            return;
        }

            std::cout<< "<h1>Edit User</h1>"
            << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
            << "<input type='hidden' name='target_user_id' value='" << target_user_id << "'>";
            std::cout << "First Name: <input type='text' name='first_name' value='" 
            << stop_xxs_function(res->getString("first_name")) << "'><br>";
            std::cout << "Last Name: <input type='text' name='last_name' value='" 
            << stop_xxs_function(res->getString("last_name")) << "'><br>";
            std::cout << "Email: <input type='text' name='email' value='" 
            << stop_xxs_function(res->getString("email")) << "'><br>";
            std::cout << "Username: <input type='text' name='username' value='" 
            << stop_xxs_function(res->getString("username")) << "'><br>";
            std::cout << "Location: <input type='text' name='location' value='" 
            << stop_xxs_function(res->getString("location")) << "'><br>";
            
        if (current_role == "admin") {
            std::string current_role_value = static_cast<std::string>(res->getString("role"));
            std::cout << "Role: <select name='role'>"
                      << "<option value='client'" << (current_role_value == "client" ? " selected" : "") << ">Client</option>"
                      << "<option value='service_provider'" << (current_role_value == "service_provider" ? " selected" : "") << ">Service Provider</option>"
                      << "<option value='admin'" << (current_role_value == "admin" ? " selected" : "") << ">Admin</option>"
                      << "</select><br>";
        } else {
            std::cout << "<input type='hidden' name='role' value='" 
                      << stop_xxs_function(res->getString("role")) << "'>";
        }
            std::cout << "<input type='submit' name='action' value='Save User Changes'>"
                  << "</form>"
                  << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
                  << "<input type='submit' name='action' value='Cancel'>"
                  << "</form>"
                  << "</body></html>";
    } catch (sql::SQLException& e) {
            std::cout << "<h1>Error loading user data</h1>"
                  << "<a href='?action=dashboard'>Back to dashboard</a></body></html>";
    }
}

void update_user(std::shared_ptr<sql::Statement> stmnt, int target_user_id, int current_user_id, const std::string& current_role) {
    if (current_role != "admin" && target_user_id != current_user_id) {
        std::cout << "<html><body><h1>Error: You can only edit your own profile</h1>"
                  << "<a href='?action=dashboard'>Back to dashboard</a></body></html>";
        return;
    }

    try {
        std::string first_name = cgi("first_name");
        std::string last_name = cgi("last_name");
        std::string email = cgi("email");
        std::string username = cgi("username");
        std::string location = cgi("location");
        std::string role = (current_role == "admin") ? cgi("role") : "";

        if (first_name.empty() || last_name.empty() || email.empty() || username.empty()) {
            std::cout << "<html><body><h1>Error: All fields are required</h1>"
                      << "<a href='javascript:history.back()'>Go back</a></body></html>";
            return;
        }
        std::string query = "UPDATE Users SET "
                          "first_name = ?, last_name = ?, email = ?, "
                          "username = ?, location = ?";
    
        if (current_role == "admin") {
            query += ", role = ?";
        }
        query += " WHERE User_id = ?";

            std::unique_ptr<sql::PreparedStatement> pstmt(
            stmnt->getConnection()->prepareStatement(query));
            pstmt->setString(1, first_name);
            pstmt->setString(2, last_name);
            pstmt->setString(3, email);
            pstmt->setString(4, username);
            pstmt->setString(5, location);
        
        if (current_role == "admin") {
            pstmt->setString(6, role);
            pstmt->setInt(7, target_user_id);
    } else {
            pstmt->setInt(6, target_user_id);
        }
        pstmt->executeUpdate();

        std::cout << "<html><body><h1>User updated successfully</h1>"
                  << "<a href='?action=dashboard'>Back to dashboard</a></body></html>";

} catch (sql::SQLException& e) {
        std::cout << "<html><body><h1>Error updating user</h1>"
                  << "<a href='?action=dashboard'>Back to dashboard</a></body></html>";
    }
}
   
int main(int argc, char **argv){

    try { //this starts a connection with Mariadb database, and then creates a stmnt, which can be passed between responses and functions to interact with the SQL data
            sql::Driver* driver = sql::mariadb::get_driver_instance();
            sql::SQLString url("jdbc:mariadb://localhost:3306/Connections_Website_Damian");
            sql::Properties properties({
            {"user", "db_user"},
            {"password", "new_password"},
            {"autoReconnect", "true"},
            {"connectTimeout", "3"}});
            std::unique_ptr<sql::Connection> conn(driver->connect(url, properties));    
            std::shared_ptr<sql::Statement> stmnt(conn->createStatement());
                    
        try {      
        auto  action = cgi.getElement("action");
        if (action->isEmpty() || action == cgi.getElements().end() || action->getValue()== "Return to Login Page") {
            login_page();}
        else if (action->getValue() == "dashboard_page" || action->getValue() == "Continue to Site") {
            dashboard(stmnt);
    }     
        else if (action->getValue() == "Login") {
    std::string user_entered_username = cgi("username");
    std::string user_entered_password = cgi("password");         
    
    try {
        std::unique_ptr<sql::PreparedStatement> pstmt(
            stmnt->getConnection()->prepareStatement(
                "SELECT User_id, role, password_hash FROM Users WHERE username = ?"));
        pstmt->setString(1, user_entered_username);
            
        std::unique_ptr<sql::ResultSet> res(pstmt->executeQuery());
     
        if (!res->next()) { 
            print_html_header("Login Error");
            std::cout<< "<h1>Error: Invalid Login Credentials (Either Username/ Password or both are wrong)</h1>"
            << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
            << "<input type='submit' name='action' value='Try Again'>"
            << "</form></body></html>";
            return 0;
        }
        
        int user_id = res->getInt("User_id");
        std::string stored_role = static_cast<std::string>(res->getString("role"));        
        std::string stored_hash = static_cast<std::string>(res->getString("password_hash"));
        std::string input_hash = picosha2::hash256_hex_string(user_entered_password);         
     
        if (stored_hash == input_hash) {
            std::string two_fa_code = generate_2fa_code();
            store_2fa_code(stmnt, user_id, two_fa_code);
            
            print_html_header("2FA Verification");
            std::cout << "<h1>Enter your 2FA code</h1>"
                      << "<p>A 6-digit code has been sent to your registered email</p>"
                        << "<br><p>Incase the 6 digit code has not been sent to your email (or the Damian_mail_spoof.txt file), please refer to the README.txt to see what the 2FA is to log in securely, or refer to begining of my report on page 3 for the code.</p>"
                      << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
                      << "<input type='hidden' name='user_id' value='" << user_id << "'>"
                      << "<input type='hidden' name='role' value='" << stored_role << "'>"
                      << "<input type='hidden' name='username' value='" << user_entered_username << "'>"
                      << "2FA Code: <input type='text' name='two_fa_code'><br>"
                      << "<input type='submit' name='action' value='Verify 2FA'>"
                      << "</form></body></html>";
        } else {
            print_html_header("Login Error");
            std::cout<< "<h1>Error: Invalid password</h1>"
            << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
            << "<input type='submit' name='action' value='Try Again'>"
            << "</form></body></html>";
        }
    }
    catch (sql::SQLException& e) {
        print_html_header("System Error");
        std::cout<< "<h1>Login Error: Please try again later</h1>"
        << "<form method='POST' action='/cgi-bin/prototype_secure_website.cgi'>"
        << "<input type='submit' name='action' value='Return to Login'>"
        << "</form></body></html>";
    }
} 
else if (action->getValue() == "Verify 2FA") {
    int user_id = std::stoi(cgi("user_id"));
    std::string role = cgi("role");
    std::string username = cgi("username");
    verify_2fa(stmnt, user_id, role, username);
}
        else if (action->getValue() == "Register" || action->getValue() ==  "Register a new user") {
            create_user();
} 
        else if (action->getValue() == "Register Account") {
            proccess_registration(stmnt);
    }
        else if (action->getValue() == "Continue to Admin Dashboard") {
            admin_dashboard(stmnt);
    }
    else if (action->getValue() == "Continue to Challenge Response Portal") {
            admin_vertification_portal(stmnt);
    }
    else if (action->getValue() == "Modify a user" || 
         action->getValue() == "Edit User" || 
         action->getValue() == "Save User Changes") {
    modify_a_user_function(stmnt);
}
    else if (action->getValue() == "logout") {
            logout();
    return 0;
}
    else if (action->getValue() == "Search") {
            search_services(stmnt);
}
else if (action->getValue() == "Request Service") {
            request_service_function(stmnt);
}
    
        else {
            login_page();
}
            }
    catch (sql::SQLException &e) {
    }}
                catch (sql::SQLException &e) {
        return 1;
             }
   return 0;
}
