// Background task orchestrator for epidemic storage
//
// This module provides task coordination for periodic maintenance
// operations and background processes related to the epidemic storage system.

use crate::error::{Result, StorageNodeError};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{debug, error, info, warn};

/// Task priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    /// Low priority task (e.g., cleanup operations)
    Low = 0,
    
    /// Normal priority task (e.g., regular synchronization)
    Normal = 1,
    
    /// High priority task (e.g., reconciliation)
    High = 2,
    
    /// Critical priority task (e.g., data loss prevention)
    Critical = 3,
}

/// Task state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Task is created but not scheduled
    Created,
    
    /// Task is queued for execution
    Queued,
    
    /// Task is currently running
    Running,
    
    /// Task is completed successfully
    Completed,
    
    /// Task failed
    Failed,
    
    /// Task was cancelled
    Cancelled,
}

/// Task metadata
#[derive(Debug, Clone)]
pub struct TaskMetadata {
    /// Task ID
    pub id: String,
    
    /// Task name
    pub name: String,
    
    /// Task type
    pub task_type: String,
    
    /// Priority
    pub priority: TaskPriority,
    
    /// State
    pub state: TaskState,
    
    /// Creation time
    pub created_at: Instant,
    
    /// Start time (if started)
    pub started_at: Option<Instant>,
    
    /// Completion time (if completed)
    pub completed_at: Option<Instant>,
    
    /// Error message (if failed)
    pub error_message: Option<String>,
    
    /// Dependencies
    pub dependencies: Vec<String>,
    
    /// Retry count
    pub retry_count: usize,
    
    /// Maximum retry count
    pub max_retries: usize,
    
    /// Context
    pub context: HashMap<String, String>,
}

/// Task definition
pub struct Task {
    /// Task metadata
    pub metadata: TaskMetadata,
    
    /// Task action function
    pub action: Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send>,
    
    /// Completion notification
    pub notify: Option<oneshot::Sender<Result<()>>>,
    
    /// Task metrics callback
    pub metrics_callback: Option<Box<dyn FnOnce(TaskMetrics) + Send>>,
}

/// Task metrics
#[derive(Debug, Clone)]
pub struct TaskMetrics {
    /// Task ID
    pub id: String,
    
    /// Success/failure
    pub success: bool,
    
    /// Duration in milliseconds
    pub duration_ms: u64,
    
    /// Retry count
    pub retry_count: usize,
    
    /// Error message (if failed)
    pub error_message: Option<String>,
}

/// Task scheduler configuration
#[derive(Debug, Clone)]
pub struct TaskSchedulerConfig {
    /// Maximum number of concurrent tasks
    pub max_concurrent_tasks: usize,
    
    /// Maximum number of tasks in queue
    pub max_queue_size: usize,
    
    /// Default task timeout in seconds
    pub default_timeout_seconds: u64,
    
    /// Default maximum retries
    pub default_max_retries: usize,
    
    /// Retry delay in milliseconds
    pub retry_delay_ms: u64,
    
    /// Scheduler tick interval in milliseconds
    pub tick_interval_ms: u64,
    
    /// Queue overflow policy
    pub overflow_policy: OverflowPolicy,
}

impl Default for TaskSchedulerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_tasks: 10,
            max_queue_size: 1000,
            default_timeout_seconds: 60,
            default_max_retries: 3,
            retry_delay_ms: 1000,
            tick_interval_ms: 100,
            overflow_policy: OverflowPolicy::RejectNew,
        }
    }
}

/// Queue overflow policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Reject new tasks when queue is full
    RejectNew,
    
    /// Drop lowest priority tasks when queue is full
    DropLowest,
    
    /// Drop oldest tasks when queue is full
    DropOldest,
}

/// Recurring task definition
struct RecurringTaskDef {
    /// Task name
    name: String,
    
    /// Task type
    task_type: String,
    
    /// Priority
    priority: TaskPriority,
    
    /// Interval in milliseconds
    interval_ms: u64,
    
    /// Last execution time
    last_execution: Option<Instant>,
    
    /// Task factory function
    factory: Box<dyn Fn() -> Task + Send + Sync>,
}

/// Task scheduler for background operations
pub struct TaskScheduler {
    /// Configuration
    config: TaskSchedulerConfig,
    
    /// Task queues (by priority)
    queues: Arc<Mutex<HashMap<TaskPriority, VecDeque<Task>>>>,
    
    /// Running tasks
    running: Arc<Mutex<HashMap<String, JoinHandle<Result<()>>>>>,
    
    /// Task metadata storage
    task_metadata: Arc<RwLock<HashMap<String, TaskMetadata>>>,
    
    /// Recurring tasks
    recurring_tasks: Arc<Mutex<Vec<RecurringTaskDef>>>,
    
    /// Control channel sender
    control_tx: mpsc::Sender<ControlMessage>,
    
    /// Control channel receiver
    control_rx: Arc<Mutex<mpsc::Receiver<ControlMessage>>>,
    
    /// Is the scheduler running
    running_flag: Arc<RwLock<bool>>,
    
    /// Running task count
    running_count: Arc<tokio::sync::Semaphore>,
}

/// Control message for scheduler
enum ControlMessage {
    /// Schedule a task
    Schedule(Task),
    
    /// Cancel a task
    Cancel(String),
    
    /// Shutdown the scheduler
    Shutdown,
}

impl TaskScheduler {
    /// Create a new task scheduler
    pub fn new(config: TaskSchedulerConfig) -> Self {
        let (control_tx, control_rx) = mpsc::channel(100);
        
        Self {
            config,
            queues: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(Mutex::new(HashMap::new())),
            task_metadata: Arc::new(RwLock::new(HashMap::new())),
            recurring_tasks: Arc::new(Mutex::new(Vec::new())),
            control_tx,
            control_rx: Arc::new(Mutex::new(control_rx)),
            running_flag: Arc::new(RwLock::new(false)),
            running_count: Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_tasks)),
        }
    }
    
    /// Start the scheduler
    pub async fn start(&self) -> Result<()> {
        {
            let mut running = self.running_flag.write().await;
            if *running {
                return Err(StorageNodeError::InvalidState {
                    context: "Scheduler is already running".to_string(),
                });
            }
            *running = true;
        }
        
        // Initialize queues
        {
            let mut queues = self.queues.lock().await;
            queues.insert(TaskPriority::Low, VecDeque::new());
            queues.insert(TaskPriority::Normal, VecDeque::new());
            queues.insert(TaskPriority::High, VecDeque::new());
            queues.insert(TaskPriority::Critical, VecDeque::new());
        }
        
        // Start the scheduler loop
        let config = self.config.clone();
        let queues = self.queues.clone();
        let running = self.running.clone();
        let task_metadata = self.task_metadata.clone();
        let recurring_tasks = self.recurring_tasks.clone();
        let control_rx = self.control_rx.clone();
        let running_flag = self.running_flag.clone();
        let running_count = self.running_count.clone();
        
        tokio::spawn(async move {
            info!("Task scheduler started");
            let mut interval = time::interval(Duration::from_millis(config.tick_interval_ms));
            
            while {
                let guard = running_flag.read().await;
                *guard
            } {
                tokio::select! {
                    _ = interval.tick() => {
                        // Check for scheduled tasks
                        Self::process_scheduled_tasks(
                            &config,
                            &queues,
                            &running,
                            &task_metadata,
                            &running_count,
                        ).await;
                        
                        // Check for recurring tasks
                        Self::process_recurring_tasks(
                            &config,
                            &recurring_tasks,
                            &queues,
                            &task_metadata,
                            &running_count,
                        ).await;
                    }
                    Some(msg) = control_rx.lock().await.recv() => {
                        match msg {
                            ControlMessage::Schedule(task) => {
                                Self::handle_schedule(
                                    &config,
                                    &queues,
                                    &task_metadata,
                                    task,
                                ).await;
                            }
                            ControlMessage::Cancel(task_id) => {
                                Self::handle_cancel(
                                    &running,
                                    &task_metadata,
                                    &task_id,
                                ).await;
                            }
                            ControlMessage::Shutdown => {
                                // Mark as not running
                                let mut guard = running_flag.write().await;
                                *guard = false;
                            }
                        }
                    }
                }
            }
            
            // Cleanup - cancel all running tasks
            let mut running_guard = running.lock().await;
            for (task_id, handle) in running_guard.drain() {
                handle.abort();
                
                // Update metadata
                let mut metadata_guard = task_metadata.write().await;
                if let Some(metadata) = metadata_guard.get_mut(&task_id) {
                    metadata.state = TaskState::Cancelled;
                    metadata.completed_at = Some(Instant::now());
                }
            }
            
            info!("Task scheduler stopped");
        });
        
        Ok(())
    }
    
    /// Schedule a task
    pub async fn schedule<F, Fut>(&self, name: &str, task_type: &str, priority: TaskPriority, action: F) -> Result<String>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        self.schedule_with_context(name, task_type, priority, HashMap::new(), action).await
    }
    
    /// Schedule a task with context
    pub async fn schedule_with_context<F, Fut>(
        &self,
        name: &str,
        task_type: &str,
        priority: TaskPriority,
        context: HashMap<String, String>,
        action: F,
    ) -> Result<String>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let task_id = format!("{}-{}", task_type, uuid::Uuid::new_v4());
        
        let metadata = TaskMetadata {
            id: task_id.clone(),
            name: name.to_string(),
            task_type: task_type.to_string(),
            priority,
            state: TaskState::Created,
            created_at: Instant::now(),
            started_at: None,
            completed_at: None,
            error_message: None,
            dependencies: Vec::new(),
            retry_count: 0,
            max_retries: self.config.default_max_retries,
            context,
        };
        
        // Create action box
        let action_box = Box::new(move || {
            let fut = action();
            Box::pin(fut) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
        });
        
        // Create oneshot channel for completion notification
        let (tx, rx) = oneshot::channel();
        
        let task = Task {
            metadata: metadata.clone(),
            action: action_box,
            notify: Some(tx),
            metrics_callback: None,
        };
        
        // Register metadata
        {
            let mut metadata_guard = self.task_metadata.write().await;
            metadata_guard.insert(task_id.clone(), metadata);
        }
        
        // Send schedule message
        self.control_tx.send(ControlMessage::Schedule(task)).await
            .map_err(|_| StorageNodeError::SendFailure {
                context: "Failed to send task schedule message".to_string(),
            })?;
            
        // Return the task ID
        Ok(task_id)
    }
    
    /// Schedule a task and wait for completion
    pub async fn schedule_and_wait<F, Fut>(
        &self,
        name: &str,
        task_type: &str,
        priority: TaskPriority,
        action: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let task_id = self.schedule(name, task_type, priority, action).await?;
        self.wait_for_task(&task_id).await
    }
    
    /// Cancel a task
    pub async fn cancel(&self, task_id: &str) -> Result<()> {
        self.control_tx.send(ControlMessage::Cancel(task_id.to_string())).await
            .map_err(|_| StorageNodeError::SendFailure {
                context: "Failed to send task cancel message".to_string(),
            })?;
            
        Ok(())
    }
    
    /// Wait for a task to complete
    pub async fn wait_for_task(&self, task_id: &str) -> Result<()> {
        let metadata_guard = self.task_metadata.read().await;
        let metadata = metadata_guard.get(task_id).ok_or_else(|| {
            StorageNodeError::NotFound {
                context: format!("Task {} not found", task_id),
            }
        })?;
        
        let state = metadata.state;
        drop(metadata_guard);
        
        match state {
            TaskState::Completed => Ok(()),
            TaskState::Failed => Err(StorageNodeError::TaskFailed {
                context: format!("Task {} failed", task_id),
            }),
            TaskState::Cancelled => Err(StorageNodeError::TaskCancelled {
                context: format!("Task {} was cancelled", task_id),
            }),
            _ => {
                // Create a channel to wait for completion
                let (tx, rx) = oneshot::channel();
                
                // Register a watcher
                self.watch_task(task_id, tx).await?;
                
                // Wait for completion
                rx.await.map_err(|_| StorageNodeError::ReceiveFailure {
                    context: format!("Failed to receive completion notification for task {}", task_id),
                })?
            }
        }
    }
    
    /// Register a recurring task
    pub async fn register_recurring<F>(
        &self,
        name: &str,
        task_type: &str,
        priority: TaskPriority,
        interval_ms: u64,
        factory: F,
    ) -> Result<()>
    where
        F: Fn() -> Task + Send + Sync + 'static,
    {
        let recurring_task = RecurringTaskDef {
            name: name.to_string(),
            task_type: task_type.to_string(),
            priority,
            interval_ms,
            last_execution: None,
            factory: Box::new(factory),
        };
        
        let mut recurring_tasks = self.recurring_tasks.lock().await;
        recurring_tasks.push(recurring_task);
        
        Ok(())
    }
    
    /// Shutdown the scheduler
    pub async fn shutdown(&self) -> Result<()> {
        self.control_tx.send(ControlMessage::Shutdown).await
            .map_err(|_| StorageNodeError::SendFailure {
                context: "Failed to send shutdown message".to_string(),
            })?;
            
        // Wait for the running flag to be set to false
        loop {
            let running = self.running_flag.read().await;
            if !*running {
                break;
            }
            drop(running);
            
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        
        Ok(())
    }
    
    /// Get current queue depths
    pub async fn get_queue_depths(&self) -> HashMap<TaskPriority, usize> {
        let queues = self.queues.lock().await;
        let mut depths = HashMap::new();
        
        for (priority, queue) in queues.iter() {
            depths.insert(*priority, queue.len());
        }
        
        depths
    }
    
    /// Get task metadata
    pub async fn get_task_metadata(&self, task_id: &str) -> Option<TaskMetadata> {
        let metadata = self.task_metadata.read().await;
        metadata.get(task_id).cloned()
    }
    
    /// Get all task metadata
    pub async fn get_all_task_metadata(&self) -> Vec<TaskMetadata> {
        let metadata = self.task_metadata.read().await;
        metadata.values().cloned().collect()
    }
    
    /// Get running task count
    pub async fn get_running_task_count(&self) -> usize {
        let running = self.running.lock().await;
        running.len()
    }
    
    /// Process scheduled tasks
    async fn process_scheduled_tasks(
        config: &TaskSchedulerConfig,
        queues: &Mutex<HashMap<TaskPriority, VecDeque<Task>>>,
        running: &Mutex<HashMap<String, JoinHandle<Result<()>>>>,
        task_metadata: &RwLock<HashMap<String, TaskMetadata>>,
        running_count: &tokio::sync::Semaphore,
    ) {
        // Check if we can run more tasks
        let permit = match running_count.try_acquire() {
            Ok(permit) => permit,
            Err(_) => return, // At max concurrency
        };
        
        // Find the highest priority task
        let task = {
            let mut queues_guard = queues.lock().await;
            
            // Check queues in priority order
            for priority in [TaskPriority::Critical, TaskPriority::High, TaskPriority::Normal, TaskPriority::Low].iter() {
                if let Some(queue) = queues_guard.get_mut(priority) {
                    if let Some(task) = queue.pop_front() {
                        // Found a task
                        return Some(task);
                    }
                }
            }
            
            None
        };
        
        // If no task found, release the permit and return
        let task = match task {
            Some(task) => task,
            None => {
                drop(permit);
                return;
            }
        };
        
        // Update task metadata
        let task_id = task.metadata.id.clone();
        {
            let mut metadata_guard = task_metadata.write().await;
            if let Some(metadata) = metadata_guard.get_mut(&task_id) {
                metadata.state = TaskState::Running;
                metadata.started_at = Some(Instant::now());
            }
        }
        
        // Create task future
        let action = task.action;
        let notify = task.notify;
        let metrics_callback = task.metrics_callback;
        
        // Create timeout future
        let timeout_duration = Duration::from_secs(config.default_timeout_seconds);
        
        // Spawn the task
        let task_future = async move {
            let start_time = Instant::now();
            
            // Keep the permit until the task completes
            let _permit = permit;
            
            // Run the task with timeout
            let result = tokio::time::timeout(timeout_duration, (action)()).await;
            
            let duration_ms = start_time.elapsed().as_millis() as u64;
            
            // Process result
            let final_result = match result {
                Ok(task_result) => task_result,
                Err(_) => Err(StorageNodeError::Timeout {
                    context: format!("Task {} timed out after {}s", task_id, config.default_timeout_seconds),
                }),
            };
            
            // Send completion notification
            if let Some(notify) = notify {
                let _ = notify.send(final_result.clone());
            }
            
            // Call metrics callback
            if let Some(callback) = metrics_callback {
                let metrics = TaskMetrics {
                    id: task_id.clone(),
                    success: final_result.is_ok(),
                    duration_ms,
                    retry_count: 0, // Not tracking retries here
                    error_message: final_result.err().map(|e| e.to_string()),
                };
                
                callback(metrics);
            }
            
            final_result
        };
        
        // Spawn the task
        let handle = tokio::spawn(task_future);
        
        // Register the running task
        {
            let mut running_guard = running.lock().await;
            running_guard.insert(task_id.clone(), handle);
        }
        
        // Create task completion checker
        let running_clone = running.clone();
        let task_metadata_clone = task_metadata.clone();
        
        tokio::spawn(async move {
            // This task monitors the completion of the scheduled task
            let result = {
                let mut running_guard = running_clone.lock().await;
                if let Some(handle) = running_guard.get(&task_id) {
                    handle.await
                } else {
                    return; // Task already completed or cancelled
                }
            };
            
            // Task completed, remove from running
            let mut running_guard = running_clone.lock().await;
            running_guard.remove(&task_id);
            
            // Update metadata
            let mut metadata_guard = task_metadata_clone.write().await;
            if let Some(metadata) = metadata_guard.get_mut(&task_id) {
                metadata.completed_at = Some(Instant::now());
                
                match result {
                    Ok(task_result) => {
                        match task_result {
                            Ok(_) => {
                                metadata.state = TaskState::Completed;
                            }
                            Err(e) => {
                                metadata.state = TaskState::Failed;
                                metadata.error_message = Some(e.to_string());
                            }
                        }
                    }
                    Err(e) => {
                        metadata.state = TaskState::Failed;
                        metadata.error_message = Some(format!("Task panicked: {}", e));
                    }
                }
            }
        });
    }
    
    /// Process recurring tasks
    async fn process_recurring_tasks(
        config: &TaskSchedulerConfig,
        recurring_tasks: &Mutex<Vec<RecurringTaskDef>>,
        queues: &Mutex<HashMap<TaskPriority, VecDeque<Task>>>,
        task_metadata: &RwLock<HashMap<String, TaskMetadata>>,
        running_count: &tokio::sync::Semaphore,
    ) {
        let now = Instant::now();
        let mut tasks_to_schedule = Vec::new();
        
        // Check recurring tasks
        {
            let mut recurring_guard = recurring_tasks.lock().await;
            
            for task in recurring_guard.iter_mut() {
                let should_run = match task.last_execution {
                    Some(last) => now.duration_since(last).as_millis() >= task.interval_ms as u128,
                    None => true, // Never run before
                };
                
                if should_run {
                    // Create a task instance
                    let task_instance = (task.factory)();
                    tasks_to_schedule.push((task.priority, task_instance));
                    task.last_execution = Some(now);
                }
            }
        }
        
        // Schedule tasks
        if !tasks_to_schedule.is_empty() {
            let mut queues_guard = queues.lock().await;
            
            for (priority, task) in tasks_to_schedule {
                let metadata = task.metadata.clone();
                
                // Register metadata
                {
                    let mut metadata_guard = task_metadata.write().await;
                    metadata_guard.insert(metadata.id.clone(), metadata);
                }
                
                // Add to queue
                let queue = queues_guard.entry(priority).or_insert_with(VecDeque::new);
                
                // Check queue size
                if queue.len() >= config.max_queue_size {
                    match config.overflow_policy {
                        OverflowPolicy::RejectNew => {
                            // Drop the task
                            continue;
                        }
                        OverflowPolicy::DropLowest => {
                            // Only drop if this is the lowest priority
                            if priority == TaskPriority::Low {
                                // Drop the task
                                continue;
                            }
                            
                            // Remove a task from the lowest priority queue
                            let lowest_queue = queues_guard.get_mut(&TaskPriority::Low);
                            if let Some(q) = lowest_queue {
                                let _ = q.pop_back();
                            }
                        }
                        OverflowPolicy::DropOldest => {
                            // Remove the oldest task from this queue
                            let _ = queue.pop_back();
                        }
                    }
                }
                
                queue.push_back(task);
            }
        }
    }
    
    /// Handle schedule control message
    async fn handle_schedule(
        config: &TaskSchedulerConfig,
        queues: &Mutex<HashMap<TaskPriority, VecDeque<Task>>>,
        task_metadata: &RwLock<HashMap<String, TaskMetadata>>,
        task: Task,
    ) {
        let priority = task.metadata.priority;
        let task_id = task.metadata.id.clone();
        
        // Add to queue
        let mut queues_guard = queues.lock().await;
        let queue = queues_guard.entry(priority).or_insert_with(VecDeque::new);
        
        // Check queue size
        if queue.len() >= config.max_queue_size {
            match config.overflow_policy {
                OverflowPolicy::RejectNew => {
                    // Mark task as cancelled
                    let mut metadata_guard = task_metadata.write().await;
                    if let Some(metadata) = metadata_guard.get_mut(&task_id) {
                        metadata.state = TaskState::Cancelled;
                        metadata.completed_at = Some(Instant::now());
                        metadata.error_message = Some("Task rejected due to queue overflow".to_string());
                    }
                    
                    // Notify task cancelled
                    if let Some(notify) = task.notify {
                        let _ = notify.send(Err(StorageNodeError::QueueFull {
                            context: "Task queue is full".to_string(),
                        }));
                    }
                    
                    return;
                }
                OverflowPolicy::DropLowest => {
                    // Only drop if this is the lowest priority
                    if priority == TaskPriority::Low {
                        // Mark task as cancelled
                        let mut metadata_guard = task_metadata.write().await;
                        if let Some(metadata) = metadata_guard.get_mut(&task_id) {
                            metadata.state = TaskState::Cancelled;
                            metadata.completed_at = Some(Instant::now());
                            metadata.error_message = Some("Task rejected due to queue overflow".to_string());
                        }
                        
                        // Notify task cancelled
                        if let Some(notify) = task.notify {
                            let _ = notify.send(Err(StorageNodeError::QueueFull {
                                context: "Task queue is full".to_string(),
                            }));
                        }
                        
                        return;
                    }
                    
                    // Remove a task from the lowest priority queue
                    let lowest_queue = queues_guard.get_mut(&TaskPriority::Low);
                    if let Some(q) = lowest_queue {
                        if let Some(dropped_task) = q.pop_back() {
                            // Mark dropped task as cancelled
                            let mut metadata_guard = task_metadata.write().await;
                            if let Some(metadata) = metadata_guard.get_mut(&dropped_task.metadata.id) {
                                metadata.state = TaskState::Cancelled;
                                metadata.completed_at = Some(Instant::now());
                                metadata.error_message = Some("Task dropped due to queue overflow".to_string());
                            }
                            
                            // Notify dropped task cancelled
                            if let Some(notify) = dropped_task.notify {
                                let _ = notify.send(Err(StorageNodeError::TaskCancelled {
                                    context: "Task dropped due to queue overflow".to_string(),
                                }));
                            }
                        }
                    }
                }
                OverflowPolicy::DropOldest => {
                    // Remove the oldest task from this queue
                    if let Some(dropped_task) = queue.pop_back() {
                        // Mark dropped task as cancelled
                        let mut metadata_guard = task_metadata.write().await;
                        if let Some(metadata) = metadata_guard.get_mut(&dropped_task.metadata.id) {
                            metadata.state = TaskState::Cancelled;
                            metadata.completed_at = Some(Instant::now());
                            metadata.error_message = Some("Task dropped due to queue overflow".to_string());
                        }
                        
                        // Notify dropped task cancelled
                        if let Some(notify) = dropped_task.notify {
                            let _ = notify.send(Err(StorageNodeError::TaskCancelled {
                                context: "Task dropped due to queue overflow".to_string(),
                            }));
                        }
                    }
                }
            }
        }
        
        // Add task to queue
        queue.push_back(task);
        
        // Update metadata
        let mut metadata_guard = task_metadata.write().await;
        if let Some(metadata) = metadata_guard.get_mut(&task_id) {
            metadata.state = TaskState::Queued;
        }
    }
    
    /// Handle cancel control message
    async fn handle_cancel(
        running: &Mutex<HashMap<String, JoinHandle<Result<()>>>>,
        task_metadata: &RwLock<HashMap<String, TaskMetadata>>,
        task_id: &str,
    ) {
        // Cancel running task
        let mut running_guard = running.lock().await;
        if let Some(handle) = running_guard.remove(task_id) {
            handle.abort();
        }
        
        // Update metadata
        let mut metadata_guard = task_metadata.write().await;
        if let Some(metadata) = metadata_guard.get_mut(task_id) {
            metadata.state = TaskState::Cancelled;
            metadata.completed_at = Some(Instant::now());
        }
    }
    
    /// Watch for task completion
    async fn watch_task(&self, task_id: &str, tx: oneshot::Sender<Result<()>>) -> Result<()> {
        // Check if task already completed
        let metadata_guard = self.task_metadata.read().await;
        let metadata = metadata_guard.get(task_id).ok_or_else(|| {
            StorageNodeError::NotFound {
                context: format!("Task {} not found", task_id),
            }
        })?;
        
        let state = metadata.state;
        drop(metadata_guard);
        
        match state {
            TaskState::Completed => {
                let _ = tx.send(Ok(()));
                return Ok(());
            }
            TaskState::Failed => {
                let error_message = metadata_guard.get(task_id)
                    .and_then(|m| m.error_message.clone())
                    .unwrap_or_else(|| "Unknown error".to_string());
                    
                let _ = tx.send(Err(StorageNodeError::TaskFailed {
                    context: error_message,
                }));
                return Ok(());
            }
            TaskState::Cancelled => {
                let _ = tx.send(Err(StorageNodeError::TaskCancelled {
                    context: format!("Task {} was cancelled", task_id),
                }));
                return Ok(());
            }
            _ => {
                // Task still running or queued, set up a watcher
                let task_metadata = self.task_metadata.clone();
                let task_id_owned = task_id.to_string();
                
                tokio::spawn(async move {
                    // Poll status until completion
                    loop {
                        // Sleep a bit to avoid tight loop
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        
                        // Check status
                        let metadata_guard = task_metadata.read().await;
                        let metadata = match metadata_guard.get(&task_id_owned) {
                            Some(m) => m,
                            None => break, // Task no longer exists
                        };
                        
                        match metadata.state {
                            TaskState::Completed => {
                                let _ = tx.send(Ok(()));
                                break;
                            }
                            TaskState::Failed => {
                                let error_message = metadata.error_message.clone()
                                    .unwrap_or_else(|| "Unknown error".to_string());
                                    
                                let _ = tx.send(Err(StorageNodeError::TaskFailed {
                                    context: error_message,
                                }));
                                break;
                            }
                            TaskState::Cancelled => {
                                let _ = tx.send(Err(StorageNodeError::TaskCancelled {
                                    context: format!("Task {} was cancelled", task_id_owned),
                                }));
                                break;
                            }
                            _ => {
                                // Still running or queued, continue polling
                            }
                        }
                        
                        drop(metadata_guard);
                    }
                });
                
                Ok(())
            }
        }
    }
}

/// EpidemicTasks manages common epidemic protocol background tasks
pub struct EpidemicTasks {
    /// Task scheduler
    scheduler: Arc<TaskScheduler>,
    
    /// Node ID
    node_id: String,
    
    /// Tasks registered
    registered_tasks: HashSet<String>,
}

impl EpidemicTasks {
    /// Create a new epidemic tasks manager
    pub fn new(node_id: String, scheduler: Arc<TaskScheduler>) -> Self {
        Self {
            scheduler,
            node_id,
            registered_tasks: HashSet::new(),
        }
    }
    
    /// Register standard recurring tasks
    pub async fn register_standard_tasks(&mut self) -> Result<()> {
        // Register gossip task
        self.register_gossip_task().await?;
        
        // Register anti-entropy task
        self.register_anti_entropy_task().await?;
        
        // Register topology update task
        self.register_topology_update_task().await?;
        
        // Register health check task
        self.register_health_check_task().await?;
        
        // Register pruning task
        self.register_pruning_task().await?;
        
        Ok(())
    }
    
    /// Register gossip task
    pub async fn register_gossip_task(&mut self) -> Result<()> {
        let task_name = "gossip";
        if self.registered_tasks.contains(task_name) {
            return Ok(());
        }
        
        // Register the task
        self.scheduler.register_recurring(
            "Gossip Protocol",
            task_name,
            TaskPriority::Normal,
            5000, // 5 seconds
            || {
                let metadata = TaskMetadata {
                    id: format!("gossip-{}", uuid::Uuid::new_v4()),
                    name: "Gossip Protocol".to_string(),
                    task_type: "gossip".to_string(),
                    priority: TaskPriority::Normal,
                    state: TaskState::Created,
                    created_at: Instant::now(),
                    started_at: None,
                    completed_at: None,
                    error_message: None,
                    dependencies: Vec::new(),
                    retry_count: 0,
                    max_retries: 3,
                    context: HashMap::new(),
                };
                
                let action = Box::new(|| {
                    Box::pin(async {
                        // This would contain the actual gossip logic
                        debug!("Running gossip protocol round");
                        
                        // Sleep to simulate work
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        
                        Ok(())
                    }) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
                });
                
                Task {
                    metadata,
                    action,
                    notify: None,
                    metrics_callback: None,
                }
            },
        ).await?;
        
        self.registered_tasks.insert(task_name.to_string());
        
        Ok(())
    }
    
    /// Register anti-entropy task
    pub async fn register_anti_entropy_task(&mut self) -> Result<()> {
        let task_name = "anti-entropy";
        if self.registered_tasks.contains(task_name) {
            return Ok(());
        }
        
        // Register the task
        self.scheduler.register_recurring(
            "Anti-Entropy Protocol",
            task_name,
            TaskPriority::Normal,
            60000, // 1 minute
            || {
                let metadata = TaskMetadata {
                    id: format!("anti-entropy-{}", uuid::Uuid::new_v4()),
                    name: "Anti-Entropy Protocol".to_string(),
                    task_type: "anti-entropy".to_string(),
                    priority: TaskPriority::Normal,
                    state: TaskState::Created,
                    created_at: Instant::now(),
                    started_at: None,
                    completed_at: None,
                    error_message: None,
                    dependencies: Vec::new(),
                    retry_count: 0,
                    max_retries: 3,
                    context: HashMap::new(),
                };
                
                let action = Box::new(|| {
                    Box::pin(async {
                        // This would contain the actual anti-entropy logic
                        debug!("Running anti-entropy protocol round");
                        
                        // Sleep to simulate work
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        
                        Ok(())
                    }) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
                });
                
                Task {
                    metadata,
                    action,
                    notify: None,
                    metrics_callback: None,
                }
            },
        ).await?;
        
        self.registered_tasks.insert(task_name.to_string());
        
        Ok(())
    }
    
    /// Register topology update task
    pub async fn register_topology_update_task(&mut self) -> Result<()> {
        let task_name = "topology-update";
        if self.registered_tasks.contains(task_name) {
            return Ok(());
        }
        
        // Register the task
        self.scheduler.register_recurring(
            "Topology Update",
            task_name,
            TaskPriority::Normal,
            30000, // 30 seconds
            || {
                let metadata = TaskMetadata {
                    id: format!("topology-update-{}", uuid::Uuid::new_v4()),
                    name: "Topology Update".to_string(),
                    task_type: "topology-update".to_string(),
                    priority: TaskPriority::Normal,
                    state: TaskState::Created,
                    created_at: Instant::now(),
                    started_at: None,
                    completed_at: None,
                    error_message: None,
                    dependencies: Vec::new(),
                    retry_count: 0,
                    max_retries: 3,
                    context: HashMap::new(),
                };
                
                let action = Box::new(|| {
                    Box::pin(async {
                        // This would contain the actual topology update logic
                        debug!("Running topology update");
                        
                        // Sleep to simulate work
                        tokio::time::sleep(Duration::from_millis(150)).await;
                        
                        Ok(())
                    }) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
                });
                
                Task {
                    metadata,
                    action,
                    notify: None,
                    metrics_callback: None,
                }
            },
        ).await?;
        
        self.registered_tasks.insert(task_name.to_string());
        
        Ok(())
    }
    
    /// Register health check task
    pub async fn register_health_check_task(&mut self) -> Result<()> {
        let task_name = "health-check";
        if self.registered_tasks.contains(task_name) {
            return Ok(());
        }
        
        // Register the task
        self.scheduler.register_recurring(
            "Health Check",
            task_name,
            TaskPriority::Normal,
            15000, // 15 seconds
            || {
                let metadata = TaskMetadata {
                    id: format!("health-check-{}", uuid::Uuid::new_v4()),
                    name: "Health Check".to_string(),
                    task_type: "health-check".to_string(),
                    priority: TaskPriority::Normal,
                    state: TaskState::Created,
                    created_at: Instant::now(),
                    started_at: None,
                    completed_at: None,
                    error_message: None,
                    dependencies: Vec::new(),
                    retry_count: 0,
                    max_retries: 3,
                    context: HashMap::new(),
                };
                
                let action = Box::new(|| {
                    Box::pin(async {
                        // This would contain the actual health check logic
                        debug!("Running health check");
                        
                        // Sleep to simulate work
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        
                        Ok(())
                    }) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
                });
                
                Task {
                    metadata,
                    action,
                    notify: None,
                    metrics_callback: None,
                }
            },
        ).await?;
        
        self.registered_tasks.insert(task_name.to_string());
        
        Ok(())
    }
    
    /// Register pruning task
    pub async fn register_pruning_task(&mut self) -> Result<()> {
        let task_name = "pruning";
        if self.registered_tasks.contains(task_name) {
            return Ok(());
        }
        
        // Register the task
        self.scheduler.register_recurring(
            "Storage Pruning",
            task_name,
            TaskPriority::Low,
            3600000, // 1 hour
            || {
                let metadata = TaskMetadata {
                    id: format!("pruning-{}", uuid::Uuid::new_v4()),
                    name: "Storage Pruning".to_string(),
                    task_type: "pruning".to_string(),
                    priority: TaskPriority::Low,
                    state: TaskState::Created,
                    created_at: Instant::now(),
                    started_at: None,
                    completed_at: None,
                    error_message: None,
                    dependencies: Vec::new(),
                    retry_count: 0,
                    max_retries: 3,
                    context: HashMap::new(),
                };
                
                let action = Box::new(|| {
                    Box::pin(async {
                        // This would contain the actual pruning logic
                        debug!("Running storage pruning");
                        
                        // Sleep to simulate work
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        
                        Ok(())
                    }) as Pin<Box<dyn Future<Output = Result<()>> + Send>>
                });
                
                Task {
                    metadata,
                    action,
                    notify: None,
                    metrics_callback: None,
                }
            },
        ).await?;
        
        self.registered_tasks.insert(task_name.to_string());
        
        Ok(())
    }
    
    /// Schedule a one-time task
    pub async fn schedule_task<F, Fut>(
        &self,
        name: &str,
        task_type: &str,
        priority: TaskPriority,
        action: F,
    ) -> Result<String>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        self.scheduler.schedule(name, task_type, priority, action).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_task_scheduler() {
        let config = TaskSchedulerConfig::default();
        let scheduler = TaskScheduler::new(config);
        
        // Start the scheduler
        scheduler.start().await.unwrap();
        
        // Schedule a task
        let task_id = scheduler.schedule(
            "Test Task",
            "test",
            TaskPriority::Normal,
            || async {
                // Simulate work
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(())
            },
        ).await.unwrap();
        
        // Wait for completion
        scheduler.wait_for_task(&task_id).await.unwrap();
        
        // Check task metadata
        let metadata = scheduler.get_task_metadata(&task_id).unwrap();
        assert_eq!(metadata.state, TaskState::Completed);
        
        // Shutdown scheduler
        scheduler.shutdown().await.unwrap();
    }
    
    #[tokio::test]
    async fn test_epidemic_tasks() {
        let config = TaskSchedulerConfig::default();
        let scheduler = Arc::new(TaskScheduler::new(config));
        
        // Start the scheduler
        scheduler.start().await.unwrap();
        
        // Create epidemic tasks
        let mut epidemic_tasks = EpidemicTasks::new("test-node".to_string(), scheduler.clone());
        
        // Register standard tasks
        epidemic_tasks.register_standard_tasks().await.unwrap();
        
        // Wait a bit to see tasks execute
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Schedule a custom task
        let task_id = epidemic_tasks.schedule_task(
            "Custom Task",
            "custom",
            TaskPriority::High,
            || async {
                // Simulate work
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(())
            },
        ).await.unwrap();
        
        // Wait for completion
        scheduler.wait_for_task(&task_id).await.unwrap();
        
        // Check task metadata
        let metadata = scheduler.get_task_metadata(&task_id).unwrap();
        assert_eq!(metadata.state, TaskState::Completed);
        
        // Shutdown scheduler
        scheduler.shutdown().await.unwrap();
    }
}
