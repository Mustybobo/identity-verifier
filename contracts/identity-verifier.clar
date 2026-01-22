;; identity-verifier.clar
;; ------------------------------------------------------------
;; Identity Verifier Contract for STX
;; - Users register identity hashes (off-chain data hashed)
;; - Admin approves/rejects/verifies
;; - Other contracts can query verified identities
;; ------------------------------------------------------------

(define-constant ERR_NOT_ADMIN u100)
(define-constant ERR_USER_NOT_FOUND u101)
(define-constant ERR_ALREADY_VERIFIED u102)
(define-constant ERR_INVALID_PARAM u103)
(define-constant ERR_INACTIVE_USER u104)

;; Admin of verifier
(define-data-var admin principal tx-sender)

;; User identity structure: hash of identity (off-chain), active bool, version counter
(define-map users
  { user: principal }
  {
    id-hash: (buff 32), ;; SHA256 hash of off-chain identity info
    active: bool,
    version: uint
  })

;; -------------------------
;; Admin functions
;; -------------------------
(define-public (set-admin (p principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err ERR_NOT_ADMIN))
    (asserts! (not (is-eq p (var-get admin))) (err ERR_INVALID_PARAM))
    (var-set admin p)
    (ok true)))

;; Deactivate user
(define-public (deactivate-user (user principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err ERR_NOT_ADMIN))
    (asserts! (not (is-eq user tx-sender)) (err ERR_INVALID_PARAM))
    (let ((u? (map-get? users { user: user })))
      (asserts! (is-some u?) (err ERR_USER_NOT_FOUND))
      (let ((user-data (unwrap! u? (err ERR_USER_NOT_FOUND))))
        (begin
          (map-set users { user: user } (merge user-data { active: false, version: (+ (get version user-data) u1) }))
          (ok true))))))

;; Reactivate user
(define-public (activate-user (user principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin)) (err ERR_NOT_ADMIN))
    (asserts! (not (is-eq user tx-sender)) (err ERR_INVALID_PARAM))
    (let ((u? (map-get? users { user: user })))
      (asserts! (is-some u?) (err ERR_USER_NOT_FOUND))
      (let ((user-data (unwrap! u? (err ERR_USER_NOT_FOUND))))
        (begin
          (map-set users { user: user } (merge user-data { active: true, version: (+ (get version user-data) u1) }))
          (ok true))))))

;; -------------------------
;; User functions
;; -------------------------
;; Register identity hash (SHA256 of off-chain identity info)
(define-public (register-identity (id-hash (buff 32)))
  (begin
    (asserts! (is-eq (len id-hash) u32) (err ERR_INVALID_PARAM))
    (let ((u? (map-get? users { user: tx-sender })))
      (asserts! (is-none u?) (err ERR_ALREADY_VERIFIED))
      (map-set users { user: tx-sender } { id-hash: id-hash, active: true, version: u1 })
      (ok true))))

;; Update identity hash
(define-public (update-identity (id-hash (buff 32)))
  (begin
    (asserts! (is-eq (len id-hash) u32) (err ERR_INVALID_PARAM))
    (let ((u? (map-get? users { user: tx-sender })))
      (asserts! (is-some u?) (err ERR_USER_NOT_FOUND))
      (let ((old (unwrap! u? (err ERR_USER_NOT_FOUND))))
        (begin
          (map-set users { user: tx-sender } (merge old { id-hash: id-hash, version: (+ (get version old) u1) }))
          (ok true))))))

;; -------------------------
;; Views
;; -------------------------
(define-read-only (is-verified (user principal))
  (let ((u? (map-get? users { user: user })))
    (if (is-none u?) (ok false) (ok (get active (unwrap-panic u?))))))

(define-read-only (get-identity-hash (user principal))
  (let ((u? (map-get? users { user: user })))
    (if (is-none u?) (err ERR_USER_NOT_FOUND) (ok (get id-hash (unwrap-panic u?))))))

(define-read-only (get-admin) (ok (var-get admin)))
