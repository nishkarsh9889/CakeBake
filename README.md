<h1>Cakebake</h1>

<p>Cakebake is a web application built using Spring Boot, Thymeleaf, Bootstrap, and MySQL. It allows users to browse, filter, and order products based on categories. Users can register or log in using the built-in authentication system or via Google OAuth2. Admins have the ability to manage product categories and add new products.</p>

<h2>Features</h2>
<ul>
  <li><strong>User Registration & Login</strong>
    <ul>
      <li>Email-based user registration.</li>
      <li>Login with email/password or Google OAuth2.</li>
    </ul>
  </li>
  <li><strong>Admin Features</strong>
    <ul>
      <li>Create and manage product categories.</li>
      <li>Add new products.</li>
    </ul>
  </li>
  <li><strong>User Features</strong>
    <ul>
      <li>Browse products by category.</li>
      <li>Place orders for products.</li>
    </ul>
  </li>
</ul>

<h2>Technologies Used</h2>
<ul>
  <li><strong>Backend:</strong> Spring Boot</li>
  <li><strong>Frontend:</strong> Thymeleaf, Bootstrap</li>
  <li><strong>Database:</strong> MySQL</li>
  <li><strong>Authentication:</strong> Spring Security with Google OAuth2</li>
</ul>

<h2>Prerequisites</h2>
<ul>
  <li>Java 17 or higher</li>
  <li>Maven 3.6+</li>
  <li>MySQL Server</li>
  <li>An active Google Developer account for OAuth2 configuration</li>
</ul>

<h2>Setup Instructions</h2>

<ol>
  <li><strong>Clone the repository:</strong>
    <pre><code>git clone https://github.com/yourusername/cakebake.git
cd cakebake
</code></pre>
  </li>

  <li><strong>Database Setup:</strong>
    <ul>
      <li>Create a MySQL database named <code>cakebake</code>.</li>
      <li>Update the <code>application.properties</code> file with your MySQL username and password:</li>
    </ul>
    <pre><code>spring.datasource.url=jdbc:mysql://localhost:3306/cakebake
spring.datasource.username=yourUsername
spring.datasource.password=yourPassword
</code></pre>
  </li>

  <li><strong>Google OAuth2 Setup:</strong>
    <ul>
      <li>Go to the <a href="https://console.developers.google.com/">Google Developers Console</a>.</li>
      <li>Create a new project and configure OAuth2 credentials.</li>
      <li>Add your client ID and secret to the <code>application.properties</code> file:</li>
    </ul>
    <pre><code>spring.security.oauth2.client.registration.google.client-id=yourClientId
spring.security.oauth2.client.registration.google.client-secret=yourClientSecret
</code></pre>
  </li>

  <li><strong>Build and Run the Application:</strong>
    <pre><code>mvn clean install
mvn spring-boot:run
</code></pre>
  </li>

  <li><strong>Access the Application:</strong>
    <ul>
      <li>Open your browser and go to <code>http://localhost:8080</code>.</li>
    </ul>
  </li>
</ol>

<h2>Application Structure</h2>
<ul>
  <li><code>src/main/java/</code>: Contains the Java code for the application, including controllers, services, repositories, and models.</li>
  <li><code>src/main/resources/templates/</code>: Contains Thymeleaf templates for the views.</li>
  <li><code>src/main/resources/static/</code>: Contains static resources like CSS, JavaScript, and images.</li>
  <li><code>src/main/resources/application.properties</code>: Configuration file for the application.</li>
</ul>

<h2>Future Enhancements</h2>
<ul>
  <li>Add payment integration.</li>
  <li>Implement order tracking and notification system.</li>
  <li>Add user reviews and ratings for products.</li>
</ul>

<h2>License</h2>
<p>This project is licensed under the MIT License.</p>
