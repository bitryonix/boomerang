use std::{any::Any, marker::PhantomData};

use tokio::sync::{mpsc, oneshot};

type EntityResult = Box<dyn Any + Send>;
type EntityCommandFn<E> = Box<dyn FnOnce(&mut E) -> EntityResult + Send + 'static>;

struct EntityCommand<E> {
    operation: EntityCommandFn<E>,
    response_tx: oneshot::Sender<EntityResult>,
}

pub struct EntityHandle<E> {
    tx: mpsc::Sender<EntityCommand<E>>,
    entity_name: &'static str,
    _marker: PhantomData<fn() -> E>,
}

impl<E> Clone for EntityHandle<E> {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
            entity_name: self.entity_name,
            _marker: PhantomData,
        }
    }
}

impl<E> EntityHandle<E>
where
    E: Send + 'static,
{
    pub async fn call<R, F>(&self, operation: F) -> R
    where
        R: Send + 'static,
        F: FnOnce(&mut E) -> R + Send + 'static,
    {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(EntityCommand {
                operation: Box::new(move |entity| Box::new(operation(entity)) as EntityResult),
                response_tx,
            })
            .await
            .unwrap_or_else(|_| panic!("{} entity channel closed", self.entity_name));

        let result = response_rx
            .await
            .unwrap_or_else(|_| panic!("{} entity task dropped response", self.entity_name));
        *result
            .downcast::<R>()
            .unwrap_or_else(|_| panic!("{} entity response type mismatch", self.entity_name))
    }
}

pub fn spawn_entity<E>(
    entity_name: &'static str,
    entity: E,
    channel_capacity: usize,
) -> EntityHandle<E>
where
    E: Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<EntityCommand<E>>(channel_capacity);

    tokio::spawn(async move {
        let mut entity = entity;
        while let Some(command) = rx.recv().await {
            let result = (command.operation)(&mut entity);
            let _ = command.response_tx.send(result);
        }
    });

    EntityHandle {
        tx,
        entity_name,
        _marker: PhantomData,
    }
}
