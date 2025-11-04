(define-constant CONTRACT_OWNER 'ST000000000000000000002AMW42H)
(define-constant ERR_UNAUTHORIZED (err u100))
(define-constant ERR_ROLE_NOT_FOUND (err u101))
(define-constant ERR_ROLE_EXPIRED (err u102))
(define-constant ERR_INVALID_DURATION (err u103))
(define-constant ERR_ALREADY_HAS_ROLE (err u104))
(define-constant ERR_INVALID_ROLE (err u105))
(define-constant ERR_CANNOT_TRANSFER_TO_SELF (err u106))
(define-constant ERR_TRANSFER_NOT_ALLOWED (err u107))
(define-constant ERR_INVALID_HISTORY_LIMIT (err u108))
(define-constant ERR_SYSTEM_FROZEN (err u109))
(define-constant ERR_SCHEDULED_ROLE_EXISTS (err u110))
(define-constant ERR_SCHEDULED_ROLE_NOT_FOUND (err u111))
(define-constant ERR_ACTIVATION_BLOCK_PASSED (err u112))
(define-constant ERR_ACTIVATION_NOT_READY (err u113))

(define-constant ROLE_ADMIN u1)
(define-constant ROLE_MODERATOR u2)
(define-constant ROLE_MEMBER u3)
(define-constant ROLE_VIEWER u4)

(define-constant MIN_DURATION u1)
(define-constant MAX_DURATION u52560000)

(define-constant ACTION_ASSIGNED "assigned")
(define-constant ACTION_REVOKED "revoked")
(define-constant ACTION_EXTENDED "extended")
(define-constant ACTION_TRANSFERRED "transferred")
(define-constant ACTION_EXPIRED "expired")
(define-constant ACTION_FROZEN "frozen")
(define-constant ACTION_UNFROZEN "unfrozen")
(define-constant ACTION_SCHEDULED "scheduled")
(define-constant ACTION_ACTIVATED "activated")
(define-constant ACTION_CANCELLED "cancelled")

(define-map user-roles
  { user: principal, role: uint }
  { assigned-at: uint, expires-at: uint, assigned-by: principal }
)

(define-map role-permissions
  uint
  { can-assign-roles: bool, can-revoke-roles: bool, can-view-users: bool, can-moderate: bool }
)

(define-data-var total-active-roles uint u0)
(define-data-var history-counter uint u0)
(define-data-var system-frozen bool false)
(define-data-var freeze-initiated-by (optional principal) none)
(define-data-var freeze-initiated-at (optional uint) none)
(define-data-var scheduled-roles-counter uint u0)

(define-map scheduled-roles
  { user: principal, role: uint }
  { 
    activation-block: uint, 
    duration: uint, 
    scheduled-by: principal, 
    scheduled-at: uint 
  }
)

(define-map role-history
  uint
  { 
    user: principal, 
    role: uint, 
    action: (string-ascii 15), 
    performed-by: principal, 
    block-height: uint, 
    details: (optional { expires-at: uint, target-user: (optional principal) })
  }
)

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

(define-private (is-system-frozen)
  (var-get system-frozen)
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

(define-private (log-role-action (user principal) (role uint) (action (string-ascii 15)) (details (optional { expires-at: uint, target-user: (optional principal) })))
  (let ((current-id (var-get history-counter)))
    (map-set role-history current-id
      {
        user: user,
        role: role,
        action: action,
        performed-by: tx-sender,
        block-height: stacks-block-height,
        details: details
      }
    )
    (var-set history-counter (+ current-id u1))
    true
  )
)

(define-public (assign-role (user principal) (role uint) (duration uint))
  (let ((current-block stacks-block-height)
        (expires-at (+ current-block duration)))
    (asserts! (not (is-system-frozen)) ERR_SYSTEM_FROZEN)
    (asserts! (has-permission tx-sender "assign") ERR_UNAUTHORIZED)
    (asserts! (is-valid-role role) ERR_INVALID_ROLE)
    (asserts! (and (>= duration MIN_DURATION) (<= duration MAX_DURATION)) ERR_INVALID_DURATION)
    (asserts! (not (is-role-active user role)) ERR_ALREADY_HAS_ROLE)
    
    (map-set user-roles
      { user: user, role: role }
      { assigned-at: current-block, expires-at: expires-at, assigned-by: tx-sender }
    )
    (var-set total-active-roles (+ (var-get total-active-roles) u1))
    (log-role-action user role ACTION_ASSIGNED (some { expires-at: expires-at, target-user: none }))
    (ok true)
  )
)

(define-public (revoke-role (user principal) (role uint))
  (begin
    (asserts! (not (is-system-frozen)) ERR_SYSTEM_FROZEN)
    (asserts! (has-permission tx-sender "revoke") ERR_UNAUTHORIZED)
    (asserts! (is-valid-role role) ERR_INVALID_ROLE)
    (asserts! (is-some (map-get? user-roles { user: user, role: role })) ERR_ROLE_NOT_FOUND)
    
    (map-delete user-roles { user: user, role: role })
    (var-set total-active-roles (- (var-get total-active-roles) u1))
    (log-role-action user role ACTION_REVOKED none)
    (ok true)
  )
)

(define-public (extend-role (user principal) (role uint) (additional-duration uint))
  (match (map-get? user-roles { user: user, role: role })
    role-data
    (let ((new-expires-at (+ (get expires-at role-data) additional-duration)))
      (asserts! (not (is-system-frozen)) ERR_SYSTEM_FROZEN)
      (asserts! (has-permission tx-sender "assign") ERR_UNAUTHORIZED)
      (asserts! (is-valid-role role) ERR_INVALID_ROLE)
      (asserts! (and (>= additional-duration MIN_DURATION) (<= additional-duration MAX_DURATION)) ERR_INVALID_DURATION)
      (asserts! (>= (get expires-at role-data) stacks-block-height) ERR_ROLE_EXPIRED)
      
      (map-set user-roles
        { user: user, role: role }
        (merge role-data { expires-at: new-expires-at })
      )
      (log-role-action user role ACTION_EXTENDED (some { expires-at: new-expires-at, target-user: none }))
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
      (log-role-action user role ACTION_EXPIRED none)
      (ok true)
    )
    ERR_ROLE_NOT_FOUND
  )
)

(define-public (transfer-role (target-user principal) (role uint))
  (let ((current-block stacks-block-height))
    (match (map-get? user-roles { user: tx-sender, role: role })
      role-data
      (begin
        (asserts! (not (is-system-frozen)) ERR_SYSTEM_FROZEN)
        (asserts! (not (is-eq tx-sender target-user)) ERR_CANNOT_TRANSFER_TO_SELF)
        (asserts! (is-valid-role role) ERR_INVALID_ROLE)
        (asserts! (>= (get expires-at role-data) current-block) ERR_ROLE_EXPIRED)
        (asserts! (not (is-role-active target-user role)) ERR_ALREADY_HAS_ROLE)
        (asserts! (or (is-eq tx-sender CONTRACT_OWNER) 
                      (>= role ROLE_MEMBER)) ERR_TRANSFER_NOT_ALLOWED)
        
        (map-delete user-roles { user: tx-sender, role: role })
        (map-set user-roles
          { user: target-user, role: role }
          { assigned-at: current-block, expires-at: (get expires-at role-data), assigned-by: tx-sender }
        )
        (log-role-action tx-sender role ACTION_TRANSFERRED (some { expires-at: (get expires-at role-data), target-user: (some target-user) }))
        (ok true)
      )
      ERR_ROLE_NOT_FOUND
    )
  )
)

(define-public (emergency-freeze-system)
  (begin
    (asserts! (or (is-eq tx-sender CONTRACT_OWNER) 
                  (is-role-active tx-sender ROLE_ADMIN)) ERR_UNAUTHORIZED)
    (asserts! (not (is-system-frozen)) ERR_SYSTEM_FROZEN)
    
    (var-set system-frozen true)
    (var-set freeze-initiated-by (some tx-sender))
    (var-set freeze-initiated-at (some stacks-block-height))
    (log-role-action tx-sender u0 ACTION_FROZEN none)
    (ok true)
  )
)

(define-public (emergency-unfreeze-system)
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (is-system-frozen) ERR_SYSTEM_FROZEN)
    
    (var-set system-frozen false)
    (var-set freeze-initiated-by none)
    (var-set freeze-initiated-at none)
    (log-role-action tx-sender u0 ACTION_UNFROZEN none)
    (ok true)
  )
)

(define-public (schedule-role (user principal) (role uint) (activation-block uint) (duration uint))
  (begin
    (asserts! (not (is-system-frozen)) ERR_SYSTEM_FROZEN)
    (asserts! (has-permission tx-sender "assign") ERR_UNAUTHORIZED)
    (asserts! (is-valid-role role) ERR_INVALID_ROLE)
    (asserts! (and (>= duration MIN_DURATION) (<= duration MAX_DURATION)) ERR_INVALID_DURATION)
    (asserts! (> activation-block stacks-block-height) ERR_ACTIVATION_BLOCK_PASSED)
    (asserts! (not (is-role-active user role)) ERR_ALREADY_HAS_ROLE)
    (asserts! (is-none (map-get? scheduled-roles { user: user, role: role })) ERR_SCHEDULED_ROLE_EXISTS)
    
    (map-set scheduled-roles
      { user: user, role: role }
      { 
        activation-block: activation-block, 
        duration: duration, 
        scheduled-by: tx-sender, 
        scheduled-at: stacks-block-height 
      }
    )
    (var-set scheduled-roles-counter (+ (var-get scheduled-roles-counter) u1))
    (log-role-action user role ACTION_SCHEDULED (some { expires-at: (+ activation-block duration), target-user: none }))
    (ok true)
  )
)

(define-public (activate-scheduled-role (user principal) (role uint))
  (match (map-get? scheduled-roles { user: user, role: role })
    scheduled-data
    (let ((current-block stacks-block-height)
          (activation-block (get activation-block scheduled-data))
          (duration (get duration scheduled-data))
          (expires-at (+ activation-block duration)))
      (asserts! (>= current-block activation-block) ERR_ACTIVATION_NOT_READY)
      (asserts! (not (is-role-active user role)) ERR_ALREADY_HAS_ROLE)
      
      (map-delete scheduled-roles { user: user, role: role })
      (var-set scheduled-roles-counter (- (var-get scheduled-roles-counter) u1))
      
      (map-set user-roles
        { user: user, role: role }
        { assigned-at: current-block, expires-at: expires-at, assigned-by: (get scheduled-by scheduled-data) }
      )
      (var-set total-active-roles (+ (var-get total-active-roles) u1))
      (log-role-action user role ACTION_ACTIVATED (some { expires-at: expires-at, target-user: none }))
      (ok true)
    )
    ERR_SCHEDULED_ROLE_NOT_FOUND
  )
)

(define-public (cancel-scheduled-role (user principal) (role uint))
  (begin
    (asserts! (has-permission tx-sender "revoke") ERR_UNAUTHORIZED)
    (asserts! (is-valid-role role) ERR_INVALID_ROLE)
    (asserts! (is-some (map-get? scheduled-roles { user: user, role: role })) ERR_SCHEDULED_ROLE_NOT_FOUND)
    
    (map-delete scheduled-roles { user: user, role: role })
    (var-set scheduled-roles-counter (- (var-get scheduled-roles-counter) u1))
    (log-role-action user role ACTION_CANCELLED none)
    (ok true)
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

(define-read-only (get-role-history-entry (history-id uint))
  (map-get? role-history history-id)
)

(define-read-only (get-history-range (start-id uint) (end-id uint))
  (if (and (<= start-id end-id) (<= (- end-id start-id) u20))
    (ok { start: start-id, end: end-id, total-entries: (var-get history-counter) })
    ERR_INVALID_HISTORY_LIMIT)
)

(define-private (min (a uint) (b uint))
  (if (<= a b) a b)
)

(define-read-only (get-total-history-entries)
  (var-get history-counter)
)

(define-read-only (is-system-frozen-status)
  (var-get system-frozen)
)

(define-read-only (get-freeze-info)
  {
    frozen: (var-get system-frozen),
    initiated-by: (var-get freeze-initiated-by),
    initiated-at: (var-get freeze-initiated-at)
  }
)

(define-read-only (get-scheduled-role (user principal) (role uint))
  (map-get? scheduled-roles { user: user, role: role })
)

(define-read-only (is-role-ready-for-activation (user principal) (role uint))
  (match (map-get? scheduled-roles { user: user, role: role })
    scheduled-data (>= stacks-block-height (get activation-block scheduled-data))
    false
  )
)

(define-read-only (get-total-scheduled-roles)
  (var-get scheduled-roles-counter)
)

(define-read-only (get-contract-info)
  {
    owner: CONTRACT_OWNER,
    total-active-roles: (var-get total-active-roles),
    total-scheduled-roles: (var-get scheduled-roles-counter),
    current-block: stacks-block-height,
    total-history-entries: (var-get history-counter),
    system-frozen: (var-get system-frozen),
    freeze-info: (get-freeze-info),
    role-constants: {
      admin: ROLE_ADMIN,
      moderator: ROLE_MODERATOR,
      member: ROLE_MEMBER,
      viewer: ROLE_VIEWER
    }
  }
)

(define-read-only (get-user-active-roles (user principal))
  {
    admin: (is-role-active user ROLE_ADMIN),
    moderator: (is-role-active user ROLE_MODERATOR),
    member: (is-role-active user ROLE_MEMBER),
    viewer: (is-role-active user ROLE_VIEWER)
  }
)
