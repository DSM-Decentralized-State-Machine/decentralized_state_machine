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
use tracing::{debug, info};

/// Type alias for async task function
pub type TaskFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// Type alias for task action function
pub type TaskActionFn = Box<dyn FnOnce() -> TaskFuture + Send>;

/// Type alias for task metrics callback function
pub type TaskMetricsCallback = Box<dyn FnOnce(TaskMetrics) + Send>;

/// Type alias for task queue map
pub type TaskQueueMap = HashMap<TaskPriority, VecDeque<Task>>;

/// Type alias for running tasks map
pub type RunningTasksMap = HashMap<String, JoinHandle<Result<()>>>;

/// Type alias for task metadata map
pub type TaskMetadataMap = HashMap<String, TaskMetadata>;

/// Task priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    pub action: TaskActionFn,

    /// Completion notification
    pub notify: Option<oneshot::Sender<Result<()>>>,

    /// Task metrics callback
    pub metrics_callback: Option<TaskMetricsCallback>,
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
#[allow(dead_code)]
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

/// Control message for scheduler
enum ControlMessage {
    /// Schedule a task
    Schedule(Task),

    /// Cancel a task
    Cancel(String),

    /// Shutdown the scheduler
    Shutdown,
}

/// Task scheduler for background operations
pub struct TaskScheduler {
    /// Configuration
    config: TaskSchedulerConfig,

    /// Task queues (by priority)
    queues: Arc<Mutex<TaskQueueMap>>,

    /// Running tasks
    running: Arc<Mutex<RunningTasksMap>>,

    /// Task metadata storage
    task_metadata: Arc<RwLock<TaskMetadataMap>>,

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

impl TaskScheduler {
    /// Create a new task scheduler
    pub fn new(config: TaskSchedulerConfig) -> Self {
        let (control_tx, control_rx) = mpsc::channel(100);
        let max_concurrent_tasks = config.max_concurrent_tasks;

        Self {
            config,
            queues: Arc::new(Mutex::new(HashMap::new())),
            running: Arc::new(Mutex::new(HashMap::new())),
            task_metadata: Arc::new(RwLock::new(HashMap::new())),
            recurring_tasks: Arc::new(Mutex::new(Vec::new())),
            control_tx,
            control_rx: Arc::new(Mutex::new(control_rx)),
            running_flag: Arc::new(RwLock::new(false)),
            running_count: Arc::new(tokio::sync::Semaphore::new(max_concurrent_tasks)),
        }
    }

    /// Start the scheduler
    pub async fn start(&self) -> Result<()> {
        {
            let mut running = self.running_flag.write().await;
            if *running {
                return Err(StorageNodeError::InvalidState(
                    "Scheduler is already running".to_string(),
                ));
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
        let queues = Arc::clone(&self.queues);
        let running = Arc::clone(&self.running);
        let task_metadata = Arc::clone(&self.task_metadata);
        let recurring_tasks = Arc::clone(&self.recurring_tasks);
        let control_rx = Arc::clone(&self.control_rx);
        let running_flag = Arc::clone(&self.running_flag);
        let running_count = Arc::clone(&self.running_count);

        tokio::spawn(async move {
            info!("Task scheduler started");
            let mut interval = time::interval(Duration::from_millis(config.tick_interval_ms));

            while {
                let guard = running_flag.read().await;
                *guard
            } {
                // Get the control receiver lock outside the select to prevent it from being dropped
                let mut control_guard = control_rx.lock().await;

                tokio::select! {
                    _ = interval.tick() => {
                        // Release the lock immediately for this branch
                        drop(control_guard);

                        // Check for scheduled tasks
                        Self::process_scheduled_tasks_impl(
                            &config,
                            &queues,
                            &running,
                            &task_metadata,
                            running_count.clone(),
                        ).await;

                        // Check for recurring tasks
                        Self::process_recurring_tasks_impl(
                            &config,
                            &recurring_tasks,
                            &queues,
                            &task_metadata,
                            running_count.clone(),
                        ).await;
                    }
                    Some(msg) = control_guard.recv() => {
                        match msg {
                            ControlMessage::Schedule(task) => {
                                Self::handle_schedule_impl(
                                    &config,
                                    &queues,
                                    &task_metadata,
                                    task,
                                ).await;
                            }
                            ControlMessage::Cancel(task_id) => {
                                Self::handle_cancel_impl(
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
    pub async fn schedule<F, Fut>(
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
        self.schedule_with_context(name, task_type, priority, HashMap::new(), action)
            .await
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
        let (tx, _rx) = oneshot::channel();

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
        self.control_tx
            .send(ControlMessage::Schedule(task))
            .await
            .map_err(|_| StorageNodeError::Internal)?;

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

    /// Cancel a task by ID
    pub async fn cancel(&self, task_id: String) -> Result<()> {
        self.control_tx
            .send(ControlMessage::Cancel(task_id.to_string()))
            .await
            .map_err(|_| StorageNodeError::Internal)?;

        Ok(())
    }

    /// Wait for a task to complete
    pub async fn wait_for_task(&self, task_id: &str) -> Result<()> {
        // Create a scope to limit the lifetime of the read guard
        let state = {
            let metadata_guard = self.task_metadata.read().await;
            let metadata = metadata_guard
                .get(task_id)
                .ok_or_else(|| StorageNodeError::NotFound(format!("Task {} not found", task_id)))?;

            metadata.state
        };

        match state {
            TaskState::Completed => Ok(()),
            TaskState::Failed => {
                // Get error message in a separate scope
                let error_message = {
                    let metadata_guard = self.task_metadata.read().await;
                    metadata_guard
                        .get(task_id)
                        .and_then(|m| m.error_message.clone())
                        .unwrap_or_else(|| "Unknown error".to_string())
                };

                Err(StorageNodeError::TaskFailed(error_message))
            }
            TaskState::Cancelled => Err(StorageNodeError::TaskCancelled(format!(
                "Task {} was cancelled",
                task_id
            ))),
            _ => {
                // Create a channel to wait for completion
                let (tx, rx) = oneshot::channel();

                // Register a watcher
                self.watch_task(task_id, tx).await?;

                // Wait for completion
                rx.await.map_err(|_| {
                    StorageNodeError::ReceiveFailure(format!(
                        "Failed to receive completion notification for task {}",
                        task_id
                    ))
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
        self.control_tx
            .send(ControlMessage::Shutdown)
            .await
            .map_err(|_| StorageNodeError::Internal)?;

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
    pub fn get_task_metadata(&self, task_id: &str) -> impl Future<Output = Option<TaskMetadata>> {
        let task_metadata = Arc::clone(&self.task_metadata);
        let task_id = task_id.to_string();

        async move {
            let metadata = task_metadata.read().await;
            metadata.get(&task_id).cloned()
        }
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

    /// Process scheduled tasks - public method that delegates to static implementation
    pub async fn process_scheduled_tasks(&self) -> Result<()> {
        Self::process_scheduled_tasks_impl(
            &self.config,
            &self.queues,
            &self.running,
            &self.task_metadata,
            Arc::clone(&self.running_count),
        )
        .await;
        Ok(())
    }

    /// Process recurring tasks - public method that delegates to static implementation
    pub async fn process_recurring_tasks(&self) -> Result<()> {
        Self::process_recurring_tasks_impl(
            &self.config,
            &self.recurring_tasks,
            &self.queues,
            &self.task_metadata,
            Arc::clone(&self.running_count),
        )
        .await;
        Ok(())
    }

    /// Handle schedule operation
    pub async fn handle_schedule(&self, task: Task) -> Result<()> {
        Self::handle_schedule_impl(&self.config, &self.queues, &self.task_metadata, task).await;
        Ok(())
    }

    /// Handle cancel operation
    pub async fn handle_cancel(&self, task_id: String) -> Result<()> {
        Self::handle_cancel_impl(&self.running, &self.task_metadata, &task_id).await;
        Ok(())
    }

    /// Internal implementation of process_scheduled_tasks
    async fn process_scheduled_tasks_impl(
        config: &TaskSchedulerConfig,
        queues: &Arc<Mutex<TaskQueueMap>>,
        running: &Arc<Mutex<RunningTasksMap>>,
        task_metadata: &Arc<RwLock<TaskMetadataMap>>,
        running_count: Arc<tokio::sync::Semaphore>,
    ) {
        // Use try_acquire_owned to get a permit we can move into the async block
        let permit = match running_count.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return, // At max concurrency
        };

        // Find the highest priority task
        let task = {
            let mut queues_guard = queues.lock().await;

            let mut found_task = None;
            for priority in [
                TaskPriority::Critical,
                TaskPriority::High,
                TaskPriority::Normal,
                TaskPriority::Low,
            ]
            .iter()
            {
                if let Some(queue) = queues_guard.get_mut(priority) {
                    if let Some(task) = queue.pop_front() {
                        found_task = Some(task);
                        break;
                    }
                }
            }

            found_task
        };

        let task = match task {
            Some(task) => task,
            None => {
                // Drop the permit if no task is found
                return;
            }
        };

        // Explicitly clone these before moving them into the future
        let task_id = task.metadata.id.clone();
        let action = task.action;
        let notify = task.notify;
        let metrics_callback = task.metrics_callback;

        // Update the metadata to show task is running
        {
            let mut metadata_guard = task_metadata.write().await;
            if let Some(metadata) = metadata_guard.get_mut(&task_id) {
                metadata.state = TaskState::Running;
                metadata.started_at = Some(Instant::now());
            }
        }

        let timeout_duration = Duration::from_secs(config.default_timeout_seconds);

        // Create explicit ownership paths for all async contexts
        let task_id_for_future = task_id.clone();
        let task_id_for_completion = task_id.clone();

        // Create a task future that can be spawned with its own dedicated task_id
        let task_future = async move {
            let start_time = Instant::now();

            // RAII guard for the semaphore permit
            let _permit = permit;

            // Execute the task with timeout
            let result = match tokio::time::timeout(timeout_duration, (action)()).await {
                Ok(task_result) => task_result,
                Err(_) => Err(StorageNodeError::Timeout),
            };

            let duration_ms = start_time.elapsed().as_millis() as u64;

            // Clone the result for the notification
            let result_for_notify = result.clone();

            // Notify completion if channel is available
            if let Some(notify) = notify {
                let _ = notify.send(result_for_notify);
            }

            // Call metrics callback if provided
            if let Some(callback) = metrics_callback {
                let metrics = TaskMetrics {
                    id: task_id_for_future.clone(),
                    success: result.is_ok(),
                    duration_ms,
                    retry_count: 0,
                    error_message: result.as_ref().err().map(|e| e.to_string()),
                };

                callback(metrics);
            }

            result
        };

        // Spawn the task
        let handle = tokio::spawn(task_future);

        // Register the running task
        {
            let mut running_guard = running.lock().await;
            running_guard.insert(task_id.clone(), handle);
        }

        // Spawn a task to handle completion - using dedicated task_id clone
        tokio::spawn({
            // Use pre-bifurcated task_id to avoid post-move borrow
            // Clone the Arc references for the completion watcher
            let running = running.clone();
            let task_metadata = task_metadata.clone();

            async move {
                // Handle running tasks in a scoped environment to limit variable lifetimes
                let handle_result = {
                    // Get and immediately remove the handle to avoid double borrow
                    let handle_opt = {
                        let mut running_guard = running.lock().await;
                        running_guard.remove(&task_id_for_completion)
                    };

                    // Execute the handle if found
                    match handle_opt {
                        Some(handle) => handle.await,
                        None => return, // Task was already removed or cancelled
                    }
                };

                // Update metadata with completion information
                let mut metadata_guard = task_metadata.write().await;
                if let Some(metadata) = metadata_guard.get_mut(&task_id_for_completion) {
                    metadata.completed_at = Some(Instant::now());

                    match handle_result {
                        Ok(task_result) => match task_result {
                            Ok(_) => {
                                metadata.state = TaskState::Completed;
                            }
                            Err(e) => {
                                metadata.state = TaskState::Failed;
                                metadata.error_message = Some(e.to_string());
                            }
                        },
                        Err(e) => {
                            metadata.state = TaskState::Failed;
                            metadata.error_message = Some(format!("Task panicked: {}", e));
                        }
                    }
                }
            }
        });
    }

    /// Internal implementation of process_recurring_tasks
    async fn process_recurring_tasks_impl(
        config: &TaskSchedulerConfig,
        recurring_tasks: &Arc<Mutex<Vec<RecurringTaskDef>>>,
        queues: &Arc<Mutex<TaskQueueMap>>,
        task_metadata: &Arc<RwLock<TaskMetadataMap>>,
        _running_count: Arc<tokio::sync::Semaphore>,
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

        // Schedule tasks in batches to avoid long lock holding
        if !tasks_to_schedule.is_empty() {
            let mut queues_guard = queues.lock().await;

            for (priority, task) in tasks_to_schedule {
                let metadata = task.metadata.clone();
                let task_id = metadata.id.clone(); // Preemptive clone to avoid ownership issues

                // Register metadata
                {
                    let mut metadata_guard = task_metadata.write().await;
                    metadata_guard.insert(task_id.clone(), metadata);
                }

                // Add to queue
                let mut queue = queues_guard.entry(priority).or_insert_with(VecDeque::new);

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

                            // We need to temporarily release our mutable borrow on the queue
                            // to avoid multiple mutable borrows

                            // Instead of dropping the reference (which does nothing), use a scope to end the borrow
                            {
                                // End the borrow scope instead of using drop()
                            }

                            // Now, try to remove a task from the lowest priority queue
                            if let Some(q) = queues_guard.get_mut(&TaskPriority::Low) {
                                if let Some(dropped_task) = q.pop_back() {
                                    // Extract the data we need from the dropped task with ownership
                                    let dropped_id = dropped_task.metadata.id.clone();
                                    let dropped_notify = dropped_task.notify;

                                    // Mark dropped task as cancelled
                                    {
                                        let mut metadata_guard = task_metadata.write().await;
                                        if let Some(metadata) = metadata_guard.get_mut(&dropped_id)
                                        {
                                            metadata.state = TaskState::Cancelled;
                                            metadata.completed_at = Some(Instant::now());
                                            metadata.error_message = Some(
                                                "Task dropped due to queue overflow".to_string(),
                                            );
                                        }
                                    }

                                    // Notify dropped task cancelled
                                    if let Some(notify) = dropped_notify {
                                        let _ = notify.send(Err(StorageNodeError::TaskCancelled(
                                            "Task dropped due to queue overflow".to_string(),
                                        )));
                                    }
                                }
                            }

                            // Re-acquire our queue reference
                            queue = queues_guard.entry(priority).or_insert_with(VecDeque::new);
                        }
                        OverflowPolicy::DropOldest => {
                            // Remove the oldest task from this queue
                            if let Some(dropped_task) = queue.pop_back() {
                                // Extract the data we need from the dropped task with ownership
                                let dropped_id = dropped_task.metadata.id.clone();
                                let dropped_notify = dropped_task.notify;

                                // Mark dropped task as cancelled
                                {
                                    let mut metadata_guard = task_metadata.write().await;
                                    if let Some(metadata) = metadata_guard.get_mut(&dropped_id) {
                                        metadata.state = TaskState::Cancelled;
                                        metadata.completed_at = Some(Instant::now());
                                        metadata.error_message =
                                            Some("Task dropped due to queue overflow".to_string());
                                    }
                                }

                                // Notify dropped task cancelled
                                if let Some(notify) = dropped_notify {
                                    let _ = notify.send(Err(StorageNodeError::TaskCancelled(
                                        "Task dropped due to queue overflow".to_string(),
                                    )));
                                }
                            }
                        }
                    }
                }

                queue.push_back(task);
            }
        }
    }

    /// Internal implementation of handle_schedule
    async fn handle_schedule_impl(
        config: &TaskSchedulerConfig,
        queues: &Arc<Mutex<TaskQueueMap>>,
        task_metadata: &Arc<RwLock<TaskMetadataMap>>,
        task: Task,
    ) {
        let priority = task.metadata.priority;
        let task_id = task.metadata.id.clone();

        // Add to queue
        let mut queues_guard = queues.lock().await;
        let mut queue = queues_guard.entry(priority).or_insert_with(VecDeque::new);

        // Check queue size
        if queue.len() >= config.max_queue_size {
            match config.overflow_policy {
                OverflowPolicy::RejectNew => {
                    // Mark task as cancelled
                    let mut metadata_guard = task_metadata.write().await;
                    if let Some(metadata) = metadata_guard.get_mut(&task_id) {
                        metadata.state = TaskState::Cancelled;
                        metadata.completed_at = Some(Instant::now());
                        metadata.error_message =
                            Some("Task rejected due to queue overflow".to_string());
                    }

                    // Notify task cancelled
                    if let Some(notify) = task.notify {
                        let _ = notify.send(Err(StorageNodeError::QueueFull(
                            "Task queue is full".to_string(),
                        )));
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
                            metadata.error_message =
                                Some("Task rejected due to queue overflow".to_string());
                        }

                        // Notify task cancelled
                        if let Some(notify) = task.notify {
                            let _ = notify.send(Err(StorageNodeError::QueueFull(
                                "Task queue is full".to_string(),
                            )));
                        }

                        return;
                    }

                    // We need to temporarily release our mutable borrow on the queue
                    // to avoid multiple mutable borrows
                    {
                        // End the borrow scope instead of using drop()
                    }

                    // Now, try to remove a task from the lowest priority queue
                    if let Some(q) = queues_guard.get_mut(&TaskPriority::Low) {
                        if let Some(dropped_task) = q.pop_back() {
                            // Extract the data we need from the dropped task
                            let dropped_id = dropped_task.metadata.id.clone();
                            let dropped_notify = dropped_task.notify;

                            // Mark dropped task as cancelled
                            {
                                let mut metadata_guard = task_metadata.write().await;
                                if let Some(metadata) = metadata_guard.get_mut(&dropped_id) {
                                    metadata.state = TaskState::Cancelled;
                                    metadata.completed_at = Some(Instant::now());
                                    metadata.error_message =
                                        Some("Task dropped due to queue overflow".to_string());
                                }
                            }

                            // Notify dropped task cancelled
                            if let Some(notify) = dropped_notify {
                                let _ = notify.send(Err(StorageNodeError::TaskCancelled(
                                    "Task dropped due to queue overflow".to_string(),
                                )));
                            }
                        }
                    }

                    // Re-acquire our queue reference
                    queue = queues_guard.entry(priority).or_insert_with(VecDeque::new);
                }
                OverflowPolicy::DropOldest => {
                    // Remove the oldest task from this queue
                    if let Some(dropped_task) = queue.pop_back() {
                        // Extract the data we need from the dropped task
                        let dropped_id = dropped_task.metadata.id.clone();
                        let dropped_notify = dropped_task.notify;

                        // Mark dropped task as cancelled
                        {
                            let mut metadata_guard = task_metadata.write().await;
                            if let Some(metadata) = metadata_guard.get_mut(&dropped_id) {
                                metadata.state = TaskState::Cancelled;
                                metadata.completed_at = Some(Instant::now());
                                metadata.error_message =
                                    Some("Task dropped due to queue overflow".to_string());
                            }
                        }

                        // Notify dropped task cancelled
                        if let Some(notify) = dropped_notify {
                            let _ = notify.send(Err(StorageNodeError::TaskCancelled(
                                "Task dropped due to queue overflow".to_string(),
                            )));
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

    /// Internal implementation of handle_cancel
    async fn handle_cancel_impl(
        running: &Arc<Mutex<RunningTasksMap>>,
        task_metadata: &Arc<RwLock<TaskMetadataMap>>,
        task_id: &str,
    ) {
        // Cancel running task
        let handle_opt = {
            let mut running_guard = running.lock().await;
            running_guard.remove(task_id)
        };

        // Abort the handle if found
        if let Some(handle) = handle_opt {
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
        // Check if task already completed - use scoped reads
        let (state, error_message) = {
            let metadata_guard = self.task_metadata.read().await;
            let metadata = metadata_guard
                .get(task_id)
                .ok_or_else(|| StorageNodeError::NotFound(format!("Task {} not found", task_id)))?;

            (metadata.state, metadata.error_message.clone())
        };

        match state {
            TaskState::Completed => {
                let _ = tx.send(Ok(()));
                Ok(())
            }
            TaskState::Failed => {
                let error_msg = error_message.unwrap_or_else(|| "Unknown error".to_string());
                let _ = tx.send(Err(StorageNodeError::TaskFailed(error_msg)));
                Ok(())
            }
            TaskState::Cancelled => {
                let _ = tx.send(Err(StorageNodeError::TaskCancelled(format!(
                    "Task {} was cancelled",
                    task_id
                ))));
                Ok(())
            }
            _ => {
                // Task still running or queued, set up a watcher
                let task_metadata = Arc::clone(&self.task_metadata);
                let task_id_owned = task_id.to_string();

                tokio::spawn(async move {
                    // Poll status until completion
                    loop {
                        // Sleep a bit to avoid tight loop
                        tokio::time::sleep(Duration::from_millis(100)).await;

                        // Use scoped read to avoid holding the lock across await points
                        let (state, error_message) = {
                            let metadata_guard = task_metadata.read().await;
                            let metadata = match metadata_guard.get(&task_id_owned) {
                                Some(m) => m,
                                None => break, // Task no longer exists
                            };

                            (metadata.state, metadata.error_message.clone())
                        };

                        match state {
                            TaskState::Completed => {
                                let _ = tx.send(Ok(()));
                                break;
                            }
                            TaskState::Failed => {
                                let error_msg =
                                    error_message.unwrap_or_else(|| "Unknown error".to_string());
                                let _ = tx.send(Err(StorageNodeError::TaskFailed(error_msg)));
                                break;
                            }
                            TaskState::Cancelled => {
                                let _ = tx.send(Err(StorageNodeError::TaskCancelled(format!(
                                    "Task {} was cancelled",
                                    task_id_owned
                                ))));
                                break;
                            }
                            _ => {
                                // Still running or queued, continue polling
                            }
                        }
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
    #[allow(dead_code)]
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
        self.scheduler
            .register_recurring(
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
                        })
                            as Pin<Box<dyn Future<Output = Result<()>> + Send>>
                    });

                    Task {
                        metadata,
                        action,
                        notify: None,
                        metrics_callback: None,
                    }
                },
            )
            .await?;

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
        self.scheduler
            .register_recurring(
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
                        })
                            as Pin<Box<dyn Future<Output = Result<()>> + Send>>
                    });

                    Task {
                        metadata,
                        action,
                        notify: None,
                        metrics_callback: None,
                    }
                },
            )
            .await?;

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
        self.scheduler
            .register_recurring(
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
                        })
                            as Pin<Box<dyn Future<Output = Result<()>> + Send>>
                    });

                    Task {
                        metadata,
                        action,
                        notify: None,
                        metrics_callback: None,
                    }
                },
            )
            .await?;

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
        self.scheduler
            .register_recurring(
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
                        })
                            as Pin<Box<dyn Future<Output = Result<()>> + Send>>
                    });

                    Task {
                        metadata,
                        action,
                        notify: None,
                        metrics_callback: None,
                    }
                },
            )
            .await?;

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
        self.scheduler
            .register_recurring(
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
                        })
                            as Pin<Box<dyn Future<Output = Result<()>> + Send>>
                    });

                    Task {
                        metadata,
                        action,
                        notify: None,
                        metrics_callback: None,
                    }
                },
            )
            .await?;

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
        self.scheduler
            .schedule(name, task_type, priority, action)
            .await
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
        let task_id = scheduler
            .schedule("Test Task", "test", TaskPriority::Normal, || async {
                // Simulate work
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(())
            })
            .await
            .unwrap();

        // Wait for completion
        scheduler.wait_for_task(&task_id).await.unwrap();

        // Check task metadata
        let metadata = scheduler.get_task_metadata(&task_id).await.unwrap();
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
        let task_id = epidemic_tasks
            .schedule_task("Custom Task", "custom", TaskPriority::High, || async {
                // Simulate work
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(())
            })
            .await
            .unwrap();

        // Wait for completion
        scheduler.wait_for_task(&task_id).await.unwrap();

        // Check task metadata
        let metadata = scheduler.get_task_metadata(&task_id).await.unwrap();
        assert_eq!(metadata.state, TaskState::Completed);

        // Shutdown scheduler
        scheduler.shutdown().await.unwrap();
    }
}
