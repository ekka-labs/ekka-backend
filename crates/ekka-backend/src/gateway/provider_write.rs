//! The gateway's provider write; only the governed driver calls it.
use super::{Gateway, GatewayError};
use openshell_proto::openshell::datamodel::v1::Provider;
use openshell_proto::openshell::v1::{CreateProviderRequest, UpdateProviderRequest};

impl Gateway {
    pub async fn write_provider(
        &self,
        bearer: &str,
        provider: Provider,
        request_id: &str,
        update: bool,
    ) -> Result<(), GatewayError> {
        if update {
            let req = Self::request(
                UpdateProviderRequest {
                    workspace_scope: self.scope(),
                    provider: Some(provider),
                    request_id: request_id.to_string(),
                    ..Default::default()
                },
                bearer,
            )?;
            self.grpc.clone().update_provider(req).await?;
        } else {
            let req = Self::request(
                CreateProviderRequest {
                    workspace_scope: self.scope(),
                    provider: Some(provider),
                    request_id: request_id.to_string(),
                },
                bearer,
            )?;
            self.grpc.clone().create_provider(req).await?;
        }
        Ok(())
    }
}
