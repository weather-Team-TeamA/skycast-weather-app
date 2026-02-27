-- Database: skycast_db
-- Generation Time: Feb 09, 2026 at 04:48 AM
-- Server version: 10.4.32-MariaDB

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

--


-- OTP Schema for SkyCast Password Reset System

CREATE TABLE IF NOT EXISTS `password_resets` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `email` VARCHAR(255) NOT NULL,
  `otp` VARCHAR(6) NOT NULL,
  `expires_at` DATETIME NOT NULL,
  `is_used` TINYINT(1) DEFAULT 0,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX (`email`),
  INDEX (`otp`)
);
----------------------------------------------------

--
-- Table structure for table `password_otps`
--

CREATE TABLE IF NOT EXISTS `password_otps` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `email` varchar(255) NOT NULL,
  `otp_hash` varchar(255) NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_sent_at` datetime DEFAULT NULL,
  `verified_at` datetime DEFAULT NULL,
  `used_at` datetime DEFAULT NULL,
  `locked_until` datetime DEFAULT NULL,
  `attempts` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `email` (`email`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `password_otps_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `otp_audit_log`
--

CREATE TABLE IF NOT EXISTS `otp_audit_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(255) DEFAULT NULL,
  `ip_address` varchar(64) NOT NULL,
  `action` varchar(32) NOT NULL,
  `success` tinyint(1) NOT NULL DEFAULT 0,
  `message` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `ip_address` (`ip_address`),
  KEY `action` (`action`),
  KEY `created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `signup_otps`
--

CREATE TABLE IF NOT EXISTS `signup_otps` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `otp_hash` varchar(255) NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_sent_at` datetime DEFAULT NULL,
  `verified_at` datetime DEFAULT NULL,
  `used_at` datetime DEFAULT NULL,
  `locked_until` datetime DEFAULT NULL,
  `attempts` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `posts`
--


-- --------------------------------------------------------

--
-- Table structure for table `saved_locations`
--

CREATE TABLE IF NOT EXISTS `saved_locations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `city_name` varchar(100) NOT NULL,
  `latitude` decimal(10,8) NOT NULL,
  `longitude` decimal(11,8) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `saved_locations_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci AUTO_INCREMENT=3;



CREATE TABLE IF NOT EXISTS `signup_otps` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `otp_hash` varchar(255) NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_sent_at` datetime DEFAULT NULL,
  `verified_at` datetime DEFAULT NULL,
  `used_at` datetime DEFAULT NULL,
  `locked_until` datetime DEFAULT NULL,
  `attempts` int(11) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


COMMIT;
