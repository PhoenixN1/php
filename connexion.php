<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

require 'db.php';
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = json_decode(file_get_contents('php://input'), true);
    
    $email = trim($data['email'] ?? '');
    $motDePasse = $data['mot_de_passe'] ?? '';

    
    if (empty($email) || empty($motDePasse)) {
        http_response_code(400);
        echo json_encode([
            'success' => false, 
            'message' => 'E-mail et mot de passe sont requis'
        ]);
        exit;
    }

    try {
        // Récupération de l'utilisateur avec TOUS les champs nécessaires
        $stmt = $pdo->prepare(
            "SELECT id, nom, email, telephone, numero_carte_nationale, mot_de_passe, role, actif, date_creation 
             FROM utilisateurs 
             WHERE email = ?"
        );
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        if (!$user) {
            http_response_code(401);
            echo json_encode([
                'success' => false, 
                'message' => 'E-mail ou mot de passe incorrect'
            ]);
            exit;
        }

        // Vérification du compte actif
        if ($user['actif'] != 1) {
            http_response_code(403);
            echo json_encode([
                'success' => false, 
                'message' => 'Votre compte est désactivé. Contactez l\'administrateur.'
            ]);
            exit;
        }

        // Vérification du mot de passe
        if (password_verify($motDePasse, $user['mot_de_passe'])) {
            // Sauvegarde de la session
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_email'] = $user['email'];
            $_SESSION['user_role'] = $user['role'];

            echo json_encode([
                'success' => true,
                'message' => 'Connexion réussie',
                'data' => [
                    'id' => (int)$user['id'],
                    'nom' => $user['nom'],
                    'email' => $user['email'],
                    'telephone' => $user['telephone'],
                    'numero_carte_nationale' => $user['numero_carte_nationale'],
                    'role' => $user['role'],
                    'actif' => (int)$user['actif'],
                    'date_creation' => $user['date_creation']
                ]
            ]);
        } else {
            http_response_code(401);
            echo json_encode([
                'success' => false, 
                'message' => 'E-mail ou mot de passe incorrect'
            ]);
        }

    } catch (PDOException $e) {
        error_log("Erreur connexion: " . $e->getMessage());
        http_response_code(500);
        echo json_encode([
            'success' => false, 
            'message' => 'Une erreur s\'est produite lors de la connexion'
        ]);
    }

} else {
    http_response_code(405);
    echo json_encode([
        'success' => false, 
        'message' => 'Méthode non autorisée'
    ]);
}
?>