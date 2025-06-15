(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_ROLE_NOT_FOUND (err u101))
(define-constant ERR_ROLE_EXPIRED (err u102))
(define-constant ERR_INVALID_DURATION (err u103))
(define-constant ERR_ALREADY_HAS_ROLE (err u104))
(define-constant ERR_INVALID_ROLE (err u105))

(define-constant ROLE_ADMIN u1)
(define-constant ROLE_MODERATOR u2)
(define-constant ROLE_MEMBER u3)
(define-constant ROLE_VIEWER u4)

(define-constant MIN_DURATION u1)
(define-constant MAX_DURATION u52560000)

(define-map user-roles
  { user: principal, role: uint }
  { assigned-at: uint, expires-at: uint, assigned-by: principal }
)

(define-map role-permissions
  uint
  { can-assign-roles: bool, can-revoke-roles: bool, can-view-users: bool, can-moderate: bool }
)

(define-data-var total-active-roles uint u0)

(map-set role-permissions ROLE_ADMIN { can-assign-roles: true, can-revoke-roles: true, can-view-users: true, can-moderate: true })
(map-set role-permissions ROLE_MODERATOR { can-assign-roles: false, can-revoke-roles: false, can-view-users: true, can-moderate: true })
(map-set role-permissions ROLE_MEMBER { can-assign-roles: false, can-revoke-roles: false, can-view-users: true, can-moderate: false })
(map-set role-permissions ROLE_VIEWER { can-assign-roles: false, can-revoke-roles: false, can-view-users: false, can-moderate: false })

(define-private (is-valid-role (role uint))
  (or (is-eq role ROLE_ADMIN)
      (or (is-eq role ROLE_MODERATOR)
          (or (is-eq role ROLE_MEMBER)
              (is-eq role ROLE_VIEWER))))
)

(define-private (is-role-active (user principal) (role uint))
  (match (map-get? user-roles { user: user, role: role })
    role-data (>= (get expires-at role-data) stacks-block-height)
    false
  )
)

(define-private (has-permission (user principal) (permission (string-ascii 20)))
  (let ((current-block stacks-block-height))
    (or (is-eq user CONTRACT_OWNER)
        (or (and (is-role-active user ROLE_ADMIN)
                 (match (map-get? role-permissions ROLE_ADMIN)
                   perms (if (is-eq permission "assign") (get can-assign-roles perms)
                           (if (is-eq permission "revoke") (get can-revoke-roles perms)
                             (if (is-eq permission "view") (get can-view-users perms)
                               (if (is-eq permission "moderate") (get can-moderate perms) false))))
                   false))
            (or (and (is-role-active user ROLE_MODERATOR)
                     (match (map-get? role-permissions ROLE_MODERATOR)
                       perms (if (is-eq permission "assign") (get can-assign-roles perms)
                               (if (is-eq permission "revoke") (get can-revoke-roles perms)
                                 (if (is-eq permission "view") (get can-view-users perms)
                                   (if (is-eq permission "moderate") (get can-moderate perms) false))))
                       false))
                (or (and (is-role-active user ROLE_MEMBER)
                         (match (map-get? role-permissions ROLE_MEMBER)
                           perms (if (is-eq permission "assign") (get can-assign-roles perms)
                                   (if (is-eq permission "revoke") (get can-revoke-roles perms)
                                     (if (is-eq permission "view") (get can-view-users perms)
                                       (if (is-eq permission "moderate") (get can-moderate perms) false))))
                           false))
                    (and (is-role-active user ROLE_VIEWER)
                         (match (map-get? role-permissions ROLE_VIEWER)
                           perms (if (is-eq permission "assign") (get can-assign-roles perms)
                                   (if (is-eq permission "revoke") (get can-revoke-roles perms)
                                     (if (is-eq permission "view") (get can-view-users perms)
                                       (if (is-eq permission "moderate") (get can-moderate perms) false))))
                           false))))))
  )
)

(define-public (assign-role (user principal) (role uint) (duration uint))
  (let ((current-block stacks-block-height)
        (expires-at (+ current-block duration)))
    (asserts! (has-permission tx-sender "assign") ERR_UNAUTHORIZED)
    (asserts! (is-valid-role role) ERR_INVALID_ROLE)
    (asserts! (and (>= duration MIN_DURATION) (<= duration MAX_DURATION)) ERR_INVALID_DURATION)
    (asserts! (not (is-role-active user role)) ERR_ALREADY_HAS_ROLE)
    
    (map-set user-roles
      { user: user, role: role }
      { assigned-at: current-block, expires-at: expires-at, assigned-by: tx-sender }
    )
    (var-set total-active-roles (+ (var-get total-active-roles) u1))
    (ok true)
  )
)

(define-public (revoke-role (user principal) (role uint))
  (begin
    (asserts! (has-permission tx-sender "revoke") ERR_UNAUTHORIZED)
    (asserts! (is-valid-role role) ERR_INVALID_ROLE)
    (asserts! (is-some (map-get? user-roles { user: user, role: role })) ERR_ROLE_NOT_FOUND)
    
    (map-delete user-roles { user: user, role: role })
    (var-set total-active-roles (- (var-get total-active-roles) u1))
    (ok true)
  )
)

(define-public (extend-role (user principal) (role uint) (additional-duration uint))
  (match (map-get? user-roles { user: user, role: role })
    role-data
    (let ((new-expires-at (+ (get expires-at role-data) additional-duration)))
      (asserts! (has-permission tx-sender "assign") ERR_UNAUTHORIZED)
      (asserts! (is-valid-role role) ERR_INVALID_ROLE)
      (asserts! (and (>= additional-duration MIN_DURATION) (<= additional-duration MAX_DURATION)) ERR_INVALID_DURATION)
      (asserts! (>= (get expires-at role-data) stacks-block-height) ERR_ROLE_EXPIRED)
      
      (map-set user-roles
        { user: user, role: role }
        (merge role-data { expires-at: new-expires-at })
      )
      (ok true)
    )
    ERR_ROLE_NOT_FOUND
  )
)

(define-public (cleanup-expired-role (user principal) (role uint))
  (match (map-get? user-roles { user: user, role: role })
    role-data
    (begin
      (asserts! (< (get expires-at role-data) stacks-block-height) ERR_ROLE_EXPIRED)
      (map-delete user-roles { user: user, role: role })
      (var-set total-active-roles (- (var-get total-active-roles) u1))
      (ok true)
    )
    ERR_ROLE_NOT_FOUND
  )
)

(define-read-only (get-user-role (user principal) (role uint))
  (map-get? user-roles { user: user, role: role })
)

(define-read-only (is-user-role-active (user principal) (role uint))
  (is-role-active user role)
)

(define-read-only (get-role-permissions (role uint))
  (map-get? role-permissions role)
)

(define-read-only (can-user-perform-action (user principal) (action (string-ascii 20)))
  (has-permission user action)
)

(define-read-only (get-role-time-remaining (user principal) (role uint))
  (match (map-get? user-roles { user: user, role: role })
    role-data
    (if (>= (get expires-at role-data) stacks-block-height)
      (ok (- (get expires-at role-data) stacks-block-height))
      (ok u0))
    ERR_ROLE_NOT_FOUND
  )
)

(define-read-only (get-total-active-roles)
  (var-get total-active-roles)
)

(define-read-only (get-contract-info)
  {
    owner: CONTRACT_OWNER,
    total-active-roles: (var-get total-active-roles),
    current-block: stacks-block-height,
    role-constants: {
      admin: ROLE_ADMIN,
      moderator: ROLE_MODERATOR,
      member: ROLE_MEMBER,
      viewer: ROLE_VIEWER
    }
  }
)